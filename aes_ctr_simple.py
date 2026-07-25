#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AES-256-CTR 流式加密/解密器,适配外部 I/O 主循环 (push API)

设计意图: 关注点分离
    处理器只持有 crypto 状态 (密钥、cipher 上下文、头部缓冲);
    调用方掌控所有 I/O (网络读、文件写) 和自己的 per-chunk 逻辑 (日志/限流/审计)。
    两边用确定正确的契约对接,互不绑架。

加密契约:
    enc = StreamingEncryptor(raw_key)
    sink.write(enc.header)              # 36 字节头部,只写一次,必须先写
    for chunk in network_reader:        # 你的主循环
        ...你的 per-chunk 操作...
        sink.write(enc.feed(chunk))     # len(out) == len(in),永远成立
    sink.write(enc.finalize())          # CTR 下返回 b'',但必须调用

解密契约 (两种模式):
    # 模式1: 原始流模式 - 从字节0喂起,处理器自己解析头部
    dec = StreamingDecryptor(raw_key)
    for chunk in network_reader:
        sink.write(dec.feed(chunk))     # 头部阶段可能返回 b''(在缓冲),见下
    sink.write(dec.finalize())

    # 模式2: 预解析头部模式 - 传输层已把头部单独成帧
    dec = StreamingDecryptor(raw_key, salt=salt, nonce=nonce)
    for chunk in network_reader:
        sink.write(dec.feed(chunk))     # 纯密文,首字节起就 1:1

解密头部阶段的长度不对称:
    解密器在累积 36 字节头部时,feed() 返回 b'' (在缓冲)。
    头部跨包完成那一次可能返回多于本次输入的字节 (尾部密文同次解出)。之后才 1:1。
    进度看 bytes_out 属性,别假设每次 len(feed())==len(in)。

说明：
  close()必须最后调用，或者使用with语句，否则你将吃到一些AttributeError，或其他异常；
  这是设计，不是漏洞

内存: O(1),不随流长度增长。处理器只持 cipher 上下文 + 至多 36 字节头部缓冲;
"""

import os

from typing import Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
# ---------------------------------------------------------------------------
# 格式与算法常量
# ---------------------------------------------------------------------------
MAGIC_NUMBER: bytes = b"CTR1"
MAGIC_LEN: int = 4
SALT_LEN: int = 16
NONCE_LEN: int = 16
HEADER_LEN: int = MAGIC_LEN + SALT_LEN + NONCE_LEN  # == 36 字节
KEY_LEN: int = 32  # AES-256 需要 32 字节密钥




# ===========================================================================
# 加密器
# ===========================================================================
class StreamingEncryptor:
    """Push 式流式 AES-256-CTR 加密器。只持 crypto 状态,调用方管所有 I/O。

    Args:
        raw_key: 用户提前生成的32字节AES-256密钥
        salt/nonce: 可选,仅用于确定性测试。生产场景务必用默认 os.urandom。
                   nonce 绝不可跨流复用 (NIST Special Publication 800-38A标准要求)。

    Raises:
        ValueError: 显式传入的 salt/nonce 长度不对。
    """

    def __init__(
        self,
        raw_key: str,
        salt: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
    ) -> None:
        self._salt: bytes = salt if salt is not None else os.urandom(SALT_LEN)
        self._nonce: bytes = nonce if nonce is not None else os.urandom(NONCE_LEN)

        if not _valid_32byte_hex(raw_key):
            raise ValueError(f"Raw key must be a {KEY_LEN*2}-character hexadecimal string ({KEY_LEN} bytes).")
        if len(self._salt) != SALT_LEN:
            raise ValueError(f"salt must be {SALT_LEN} bytes, got {len(self._salt)}")
        if len(self._nonce) != NONCE_LEN:
            raise ValueError(f"nonce must be {NONCE_LEN} bytes, got {len(self._nonce)}")

        # 密钥不超出本对象生命周期存储
        self._key: bytes = _derive_key(raw_key, self._salt)

        # 单个 encryptor 跨所有 feed() 复用 -> counter 连续。这是流式 CTR
        # 正确性的关键: 拆成任意分块,产出和一次性加密整段字节相同。
        self._encryptor = _stream_cipher(self._key, self._nonce, encrypt=True)

        # 预构建的 36 字节头部: magic | salt | nonce
        self._header: bytes = MAGIC_NUMBER + self._salt + self._nonce

        self._finalized: bool = False
        self._bytes_in: int = 0  # 已喂入的明文字节

    # ------------------------------------------------------------------ API

    @property
    def header(self) -> bytes:
        """36 字节头部 (magic | salt | nonce)。
        调用方必须在任何 feed() 输出之前把它写入 sink 一次。处理器**故意不跟踪**
        调用方是否已写 —— 那是 I/O 关注点,归调用方管。
        """
        return self._header

    @property
    def salt(self) -> bytes:
        return self._salt

    @property
    def nonce(self) -> bytes:
        return self._nonce

    @property
    def bytes_in(self) -> int:
        """已通过 feed() 喂入的明文字节总数。"""
        return self._bytes_in

    def feed(self, chunk: bytes) -> bytes:
        """加密一块,立即返回密文。

        * len(out) == len(in) 永远成立 (CTR 流密码无 padding),进度可精确核算。
        * 任意大小、变长分块都行 (真实 socket recv 就是变长),counter 跨调用正确递增。
        * 喂 b'' 是 no-op,返回 b'' (EOF 前无害)。
        * finalize() 之后调用抛 RuntimeError。
        * 零内部缓冲: 返回值就是 encryptor.update(chunk) 的直接输出,不攒任何东西。
          喂 1B 返 1B,喂 1TB 返 1TB —— 块大小是调用方的决策和后果,我只保证结果对。
          生产场景落在 KB-MB 区间最舒服: 太小 FFI 主导(慢),太大内存爆炸+不可中断。
        """
        if self._finalized:
            raise RuntimeError("encryptor has been finalized; cannot feed()")
        if not chunk:
            return b""
        out = self._encryptor.update(chunk)
        self._bytes_in += len(chunk)
        return out

    # 关注点：只负责业务和校验，不越界处理物理释放。
    def finalize(self) -> bytes:
        """关闭流。返回尾部字节 (CTR 下为 b'')。

        必须在流末尾调用: 把处理器翻成终态,之后再调用feed() 抛异常而非静默忽略错误;
        同时确定性释放 OpenSSL 的 EVP_CIPHER_CTX。
        cryptography 库的 CTR 实现下返回 0 字节 (不是 16 字节 —— 那是集成派
        如 Java JCE/PyCryptodome 的语义,本库是分离派)。
        将来加 HMAC/GCM 时,tag 就在这里返回,调用方追加到 sink。
        
        finalize完成后，再次调用时，抛 RuntimeError
        """
        if self._finalized:
            raise RuntimeError("encryptor already finalized")
        tail = self._encryptor.finalize()  # CTR 下返回 b''
        self._finalized = True
        return tail

    # 关注点：只负责清理物理资源，不篡改业务状态。
    def close(self):
        try:
            # 尝试帮助_encryptor清理资源，但不强制要求成功
            if self._encryptor:
                self._encryptor.finalize()
        except Exception: # noqa
            pass

        try:
            #清除内存中的敏感数据（减少暴露窗口）
            del self._key
        except AttributeError:
            pass

    def __enter__(self) -> "StreamingEncryptor":
        return self

    # 关注点：只是在with情景下，替代用户手动调close()。
    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

# ===========================================================================
# 解密器
# ===========================================================================
class StreamingDecryptor:
    """Push 式流式 AES-256-CTR 解密器。只持 crypto 状态,调用方管所有 I/O。

    两种构造模式:

    1. **原始流模式** (默认, 不传 salt/nonce): 从字节 0 喂起,处理器内部缓冲到
       36 字节头部凑齐,校验 magic,派生密钥,再解密剩余字节。契合"读网络->feed"
       的自然循环,调用方不用自己解析头部。
        重要:
       头部阶段（含跨包完成的那次）：len(out) < len(in)（因为头部字节被缓冲并丢弃，头部字节不产出明文）。
       进入 BODY阶段 后：len(out) == len(in)（纯流式 1:1）。进度看 bytes_out。
       进度看 bytes_out。

    2. **预解析头部模式** (同时传 salt 和 nonce): 传输层已把头部单独成帧 (如长度
       前缀头帧) 时用。跳过头部解析和 magic 校验,feed() 从首字节起就是纯密文 1:1。

    安全边界: 纯 CTR 无完整性校验。篡改密文静默产出垃圾不报错,错密码也静默。

    Args:
        raw_key: 用户提前生成的32字节AES-256密钥。
        salt/nonce: 预解析头部模式用,必须同时传或同时不传。

    Raises:
        ValueError: magic 错 / salt nonce 长度不对 / 只传其一 / 流在头部完成前结束。
        RuntimeError: finalize 后再调 feed/finalize。
    """

    # 状态机状态值: _STATE_HEADER = 累积头部中; _STATE_BODY = 头部已解析,正在解密
    _STATE_HEADER = "header"
    _STATE_BODY = "body"

    def __init__(
        self,
        raw_key: str,
        salt: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
    ) -> None:
        if not _valid_32byte_hex(raw_key):
            raise ValueError(f"Raw key must be a {KEY_LEN*2}-character hexadecimal string ({KEY_LEN} bytes).")
        if (salt is None) != (nonce is None):
            raise ValueError("salt and nonce must be supplied together, or neither.")

        self._raw_key: Optional[str] = raw_key
        self._buffer: bytearray = bytearray()  # 头部累积器,仅 header 阶段用,≤36B
        self._magic_checked: bool = False
        self._salt: Optional[bytes] = None
        self._nonce: Optional[bytes] = None
        self._key: Optional[bytes] = None
        self._decryptor = None
        self._finalized: bool = False
        self._bytes_in: int = 0   # 已喂入的原始流字节 (头部+密文)
        self._bytes_out: int = 0  # 已返回的明文字节

        if salt is not None and nonce is not None:
            # 预解析头部模式: 直接进 body 阶段,无头部缓冲
            if len(salt) != SALT_LEN:
                raise ValueError(f"salt must be {SALT_LEN} bytes, got {len(salt)}")
            if len(nonce) != NONCE_LEN:
                raise ValueError(f"nonce must be {NONCE_LEN} bytes, got {len(nonce)}")
            self._salt = salt
            self._nonce = nonce
            self._key = _derive_key(raw_key, salt)
            self._decryptor = _stream_cipher(self._key, nonce, encrypt=False)
            self._raw_key = None  # 丢引用,密钥已在 cipher 上下文里
            self._state = self._STATE_BODY
            self._magic_checked = True
        else:
            # 原始流模式: 头部从入站字节解析
            self._state = self._STATE_HEADER

    # ------------------------------------------------------------------ API

    @property
    def header_ready(self) -> bool:
        """36 字节头部已收齐并解析完毕时为 True。"""
        return self._state == self._STATE_BODY

    @property
    def header(self) -> Optional[bytes]:
        """已解析的 36 字节头部,header_ready 之前为 None。"""
        if self._state == self._STATE_BODY:
            return MAGIC_NUMBER + self._salt + self._nonce
        return None

    @property
    def salt(self) -> Optional[bytes]:
        return self._salt

    @property
    def nonce(self) -> Optional[bytes]:
        return self._nonce

    @property
    def bytes_in(self) -> int:
        """已喂入的原始流字节总数 (头部+密文)。"""
        return self._bytes_in

    @property
    def bytes_out(self) -> int:
        """已返回的明文字节总数。权威进度指标,别用每次 feed() 的返回长度。"""
        return self._bytes_out

    def feed(self, chunk: bytes) -> bytes:
        """喂入原始流字节,返回已就绪可写的明文。

        * 头部阶段 (仅原始流模式) 可能返回 b'' (在缓冲),头部跨包完成那一次返回少于
         本次输入的字节 (头部被丢弃，尾部密文同次解出)。用 bytes_out 看进度。
        * body 阶段 (及预解析头部模式的全程) 输出长度 == 输入长度。
        * 喂 b'' 是 no-op 返回 b''。
        * magic 错抛 ValueError。finalize 后调抛 RuntimeError。
        """
        if self._finalized:
            raise RuntimeError("decryptor has been finalized; cannot feed()")
        if not chunk:
            return b""
        self._bytes_in += len(chunk)

        if self._state == self._STATE_HEADER:
            self._buffer.extend(chunk)

            # 凑齐 4 字节 magic 就立即 fail-fast,不等满 36 字节
            if not self._magic_checked and len(self._buffer) >= MAGIC_LEN:
                if bytes(self._buffer[:MAGIC_LEN]) != MAGIC_NUMBER:
                    raise ValueError(
                        f"Bad magic number: expected {MAGIC_NUMBER!r}, got "
                        f"{bytes(self._buffer[:MAGIC_LEN])!r}. "
                        f"Not a CTR1 encrypted stream."
                    )
                self._magic_checked = True

            # 头部还没凑齐 -> 继续缓冲
            if len(self._buffer) < HEADER_LEN:
                return b""

            # 头部完成: 解析 salt/nonce,派生密钥,建 decryptor
            self._salt = bytes(self._buffer[MAGIC_LEN:MAGIC_LEN + SALT_LEN])
            self._nonce = bytes(self._buffer[MAGIC_LEN + SALT_LEN:HEADER_LEN])
            self._key = _derive_key(self._raw_key, self._salt)
            self._decryptor = _stream_cipher(self._key, self._nonce, encrypt=False)
            self._raw_key = None  # 尽早丢引用

            # 头部之后的字节是密文,立即解密返回
            body = bytes(self._buffer[HEADER_LEN:])
            self._buffer = bytearray()
            self._state = self._STATE_BODY
            out = self._decryptor.update(body)
            self._bytes_out += len(out)
            return out

        # ---- body 阶段: 直通式流解密,零缓冲 ----
        out = self._decryptor.update(chunk)
        self._bytes_out += len(out)
        return out

    # 关注点：只负责业务和校验，不越界处理资源释放。
    def finalize(self) -> bytes:
        """关闭流。返回尾部字节 (CTR 下为 b'')。
        
        finalize完成后，再次调用时，抛 RuntimeError
        流末尾必须调用。若流在 36 字节头部完成前结束 (截断输入) 抛 EOFError。
        """
        if self._finalized:
            raise RuntimeError("decryptor already finalized")

        # 头部未完成意味着流已截断或格式错误，解密器无法继续。
        if self._state == self._STATE_HEADER:
            raise EOFError(
                f"Stream ended before header was complete: got only "
                f"{len(self._buffer)} of {HEADER_LEN} header bytes."
            )

        # 状态机与底层资源不一致
        if self._decryptor is None:
            raise AssertionError("Decryptor logic bug: _state == BODY but _decryptor is None")

        tail = self._decryptor.finalize()  # CTR 下返回 b''
        self._bytes_out += len(tail)
        self._finalized = True
        return tail

    # 关注点：只负责清理物理资源，不篡改业务状态。
    def close(self):
        try:
            # 尝试帮助_decryptor清理资源，但不强制要求成功
            if self._decryptor:
                self._decryptor.finalize()
        except Exception: # noqa
            pass

        # 清除内存中的敏感数据（减少暴露窗口）
        try:
            del self._key
        except AttributeError:
            pass

        try:
            del self._raw_key
        except AttributeError:
            pass

    def __enter__(self) -> "StreamingDecryptor":
        return self

    # 关注点：只是在with情景下，替代用户手动调close()
    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()



# ===========================================================================
# 内部工具函数
# ===========================================================================
def _valid_32byte_hex(s: str) -> bool:
    # 检查长度 十六进制字符数 = 2 × 原始字节数
    if len(s) != 2 * KEY_LEN:
        return False
    try:
        bytes.fromhex(s)
        return True
    except ValueError:
        return False

def _derive_key(raw_key: str, salt: bytes) -> bytes:
    """使用 HMAC-SHA256 对原始密钥进行加盐多样化（单次哈希，极快）

    """
    h = hmac.HMAC(bytes.fromhex(raw_key), hashes.SHA256(), backend=default_backend())
    h.update(salt)
    return h.finalize()

def _stream_cipher(key: bytes, nonce: bytes, encrypt: bool):
    """创建 CTR 流式 cipher 上下文 (encryptor 或 decryptor)。

    关键: CTR 是流密码,底层 OpenSSL 在同一个 cipher 对象上**跨 update() 调用**
    维护 128 位大端 counter。所以一个上下文可以喂任意大小的分块,产出和"一次性
    加密整段"完全相同的字节流。这正是流式 I/O 在 CTR 下安全的根因。
    AES 的 16 字节块作用在**密钥流生成侧** (E_K(counter)),明文侧是逐字节 XOR,
    所以 update(1B) 也立即返回 1 字节,剩余 15 字节密钥流缓存在 OpenSSL 内部。
    """
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    return cipher.encryptor() if encrypt else cipher.decryptor()

if __name__ == "__main__":
    row_key = os.urandom(KEY_LEN).hex()
    print(f"生成随机密钥(如果决定使用，请妥善保管，本函数每次输出内容随机)：{row_key}")
