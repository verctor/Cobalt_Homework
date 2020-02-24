# Beacon C2 Protocol

## Overview

该文档分为以下几个部分：

* overview：简单介绍
* Key Exchange：描述beacon通信过程中的key exchange过程
* metadata：描述beacon metadata的相关信息
* Command：描述beacon的task/command如何下发，C2数据包如何构造，command定义如何
* Result：描述beacon的result数据包格式，如何解析，各种结果的定义

由于不知道怎么表示二进制数据结构，随便编了一个：

```
task {
  4 command = big_endian int;  // <长度,单位字节> <字段名> = [字节序] <java里的类型>
  4 length = big_endian int;
};
```



## Key Exchange

每个beacon生成自己的session key，放入metadata，使用RSA/PKCS1PADDING加密metadata，公钥长度为1024bit，然后发送给服务端

tasks和results使用AES128/CBC模式加密，padding为简单填充至16倍数，密文末尾使用HMACSHA256对密文做消息验证，但是验证码只取前16字节。

RSA公私钥存放文件为`.cobaltstrike.beacon_keys`，为java序列化对象的二进制格式，想导出public key暂时想到两种方法：

* java readObject，但是要用cobaltstrike sleep库
* 通过external c2导出stage，然后直接导出public key，这也是我脚本里用到的，不用编译java，没什么依赖

## metadata

metadata主要包括以下字段：

| 名称           | 含义                                                         | 偏移     |
| -------------- | ------------------------------------------------------------ | -------- |
| session key    | 生成AES128加密密钥和HMACSHA256 hash密钥的密码                | [0, 16)  |
| ANSI code page | windows gui所用的代码页                                      | [16, 18) |
| OEM code page  | windows console所用的代码页                                  | [18, 20) |
| id             | beacon id                                                    | 0        |
| pid            | beacon进程的pid                                              | 1        |
| ver            | 用来表示系统版本和ssh版本                                    | 2        |
| intz           | 内网地址                                                     | 3        |
| comp           | computer name                                                | 4        |
| user           | 创建beacon进程的用户，如果末尾加上了`[空格]*`表示是管理员并且完整性级别最高 | 5        |
| is64           | beacon是否在x64系统上                                        | 6        |
| barch          | beacon进程是否是64位进程                                     | 7        |
| port           | ssh port                                                     | 8        |

上面表格表示的偏移形如`[0, 16)`，表示metadata二进制数据起始偏移和终止偏移

上面表格表示的偏移形如`0`指metadata根据`\t`分割字符串后的数组索引

metadata的各类字段以上面偏移为说明，如果偏移5的字段不存在（分割字符串后数组索引为5），那么之后的字段也就不会读取了。



## Command

单个task是以以下格式

```c
task {
  4 command = big_endian int;
  4 length = big_endian int;
  length content = byte[];
};
```

可以多个task一起发送，beacon会根据长度来分割这些task。

```c
tasks {
    task;
    task;
    task;
    ...  // 多个
};
```

加密前还会给tasks加上点别的信息，用来防重放：

padding为`'A' * padding_len`，不过其实用其他字符也可以，因为解密的时候不会检查这个

```c
tasks_before_encrypt {
    4 current_time = big_endian int;
    4 tasks_len = big_endian int;
    tasks_len tasks = byte[];
    padding_len padding = byte[];  // padding_len = (16 - ((4 + 4 + tasks_len) % 16)) % 16
};
```

加密后的密文会附上hmac

```c
tasks_encrypted {
    tasks_before_encrypt_len ciphertext = byte[];
    16 hmac = byte[];
};
```

最后发送给beacon

beacon支持的c2命令有，通过强大的idea搜索加`script/utils.py`脚本调试得出，但是似乎仍有缺少的部分：

```java
    'COMMAND_SPAWN' : 1,
    'COMMAND_SHELL' : 2,
    'COMMAND_DIE' : 3,
    'COMMAND_SLEEP' : 4,
    'COMMAND_CD' : 5,
    'COMMAND_KEYLOG_START' : 6,
    'COMMAND_KEYLOG_STOP' : 7,
    'COMMAND_CHECKIN': 8,
    'COMMAND_INJECT_PID' : 9,
    'COMMAND_UPLOAD' : 10,
    'COMMAND_DOWNLOAD': 11,
    'COMMAND_EXECUTE': 12,
    'COMMAND_SPAWN_PROC_X86' : 13,
    'COMMAND_INJECT_PING' : 18,
    'COMMAND_DOWNLOAD_CANCEL': 19,
    'COMMAND_FORWARD_PIPE_DATA': 22,
    'COMMAND_UNLINK': 23,
    'COMMAND_PIPE_PONG': 24,
    'COMMAND_GET_SYSTEM': 25,
    'COMMAND_GETUID': 27,
    'COMMAND_REV2SELF': 28,
    'COMMAND_TIMESTOMP': 29,
    'COMMAND_STEALTOKEN': 31,
    'COMMAND_PS': 32,
    'COMMAND_KILL': 33,
    'COMMAND_KerberosTicketUse': 34,
    'COMMAND_Kerberos_Ticket_Purge': 35,
    'COMMAND_POWERSHELL_IMPORT': 37,
    'COMMAND_RUNAS': 38,
    'COMMAND_PWD': 39,
    'COMMAND_JOB_REGISTER' : 40,
    'COMMAND_JOBS': 41,
    'COMMAND_JOB_KILL': 42,
    'COMMAND_INJECTX64_PID' : 43,
    'COMMAND_SPAWNX64' : 44,
    'COMMAND_VNC_INJECT': 45,
    'COMMAND_VNC_INJECT_X64': 46,
    'COMMAND_PAUSE': 47,
    'COMMAND_IPCONFIG': 48,
    'COMMAND_MAKE_TOKEN': 49,
    'COMMAND_PORT_FORWARD': 50,
    'COMMAND_PORT_FORWARD_STOP': 51,
    'COMMAND_BIND_STAGE': 52,
    'COMMAND_LS': 53,
    'COMMAND_MKDIR': 54,
    'COMMAND_DRIVERS': 55,
    'COMMAND_RM': 56,
    'COMMAND_STAGE_REMOTE_SMB': 57,
    'COMMAND_START_SERVICE': 58,  # not sure
    'COMMAND_HTTPHOSTSTRING': 59,
    'COMMAND_OPEN_PIPE': 60,
    'COMMAND_CLOSE_PIPE': 61,
    'COMMAND_JOB_REGISTER_IMPERSONATE' : 62,
    'COMMAND_SPAWN_POWERSHELLX86' : 63,
    'COMMAND_SPAWN_POWERSHELLX64' : 64,
    'COMMAND_INJECT_POWERSHELLX86_PID' : 65,
    'COMMAND_INJECT_POWERSHELLX64_PID' : 66,
    'COMMAND_UPLOAD_CONTINUE' : 67,
    'COMMAND_PIPE_OPEN_EXPLICIT' : 68,
    'COMMAND_SPAWN_PROC_X64' : 69,
    'COMMAND_JOB_SPAWN_X86' : 70,
    'COMMAND_JOB_SPAWN_X64' : 71,
    'COMMAND_SETENV' : 72,
    'COMMAND_FILE_COPY' : 73,
    'COMMAND_FILE_MOVE' : 74,
    'COMMAND_PPID' : 75,
    'COMMAND_RUN_UNDER_PID' : 76,
    'COMMAND_GETPRIVS' : 77,
    'COMMAND_EXECUTE_JOB' : 78,
    'COMMAND_PSH_HOST_TCP' : 79,
    'COMMAND_DLL_LOAD' : 80,
    'COMMAND_REG_QUERY' : 81,
    'COMMAND_LSOCKET_TCPPIVOT' : 82,
    'COMMAND_ARGUE_ADD' : 83,
    'COMMAND_ARGUE_REMOVE' : 84,
    'COMMAND_ARGUE_LIST' : 85,
    'COMMAND_TCP_CONNECT' : 86,
    'COMMAND_JOB_SPAWN_TOKEN_X86' : 87,
    'COMMAND_JOB_SPAWN_TOKEN_X64' : 88,
    'COMMAND_SPAWN_TOKEN_X86' : 89,
    'COMMAND_SPAWN_TOKEN_X64' : 90,
    'COMMAND_INJECTX64_PING' : 91,
    'COMMAND_BLOCKDLLS' : 92,
```





## Result

返回结果为多个job的result：

```c
results {
    result_encrypted;
    result_encrypted;
   	...
};
```

单个加密的result是包含长度和密文还有hmac的

```c
result_encrypted {
    4 cipher_hmac_len = big_endian int;
  	cipher_len cipher_text = byte[];
    16 hmac = byte[];
};
```

与task一样，result包含时间用来防重放

```c
result_decrypt {
	4 timestamp = big_endian int;
    4 length = big_endian int;
    length result = byte[];
};
```

最后的结构为：

```c
result {
    4 job_type = big_endian int;
    (length-4) result_data = byte[];
};
```



结果类型的定义有：

```java
    'CALLBACK_OUTPUT' : 0,
    'CALLBACK_KEYSTROKES' : 1,
    'CALLBACK_FILE' : 2,
    'CALLBACK_SCREENSHOT' : 3,
    'CALLBACK_CLOSE' : 4,
    'CALLBACK_READ' : 5,
    'CALLBACK_CONNECT' : 6,
    'CALLBACK_PING' : 7,
    'CALLBACK_FILE_WRITE' : 8,
    'CALLBACK_FILE_CLOSE' : 9,
    'CALLBACK_PIPE_OPEN' : 10,
    'CALLBACK_PIPE_CLOSE' : 11,
    'CALLBACK_PIPE_READ' : 12,
    'CALLBACK_POST_ERROR' : 13,
    'CALLBACK_PIPE_PING' : 14,
    'CALLBACK_TOKEN_STOLEN' : 15,
    'CALLBACK_TOKEN_GETUID' : 16,
    'CALLBACK_PROCESS_LIST' : 17,
    'CALLBACK_POST_REPLAY_ERROR' : 18,
    'CALLBACK_PWD' : 19,
    'CALLBACK_JOBS' : 20,
    'CALLBACK_HASHDUMP' : 21,
    'CALLBACK_PENDING' : 22,
    'CALLBACK_ACCEPT' : 23,
    'CALLBACK_NETVIEW' : 24,
    'CALLBACK_PORTSCAN' : 25,
    'CALLBACK_DEAD' : 26,
    'CALLBACK_SSH_STATUS' : 27,
    'CALLBACK_CHUNK_ALLOCATE' : 28,
    'CALLBACK_CHUNK_SEND' : 29,
    'CALLBACK_OUTPUT_OEM' : 30,
    'CALLBACK_ERROR' : 31,
    'CALLBACK_OUTPUT_UTF8' : 32
```



