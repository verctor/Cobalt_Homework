# Overview

定义了beacon的metadata和校验的逻辑

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

# 分析

## 构造函数

`common.BeaconEntry#BeaconEntry`

```java
    public BeaconEntry(final byte[] original, final String chst, final String ext) {
        this.id = "";
        this.pid = "";
        this.ver = "";
        this.intz = "";
        this.comp = "";
        this.user = "";
        this.is64 = "0";
        this.ext = "";
        this.last = System.currentTimeMillis();
        this.diff = 0L;
        this.state = 0;
        this.hint = 0;
        this.pbid = "";
        this.note = "";
        this.barch = "x86";
        this.alive = true;
        this.port = "";
        this.sane = false;
        this.chst = null;
        // 跳过session key和代码页的字节，metadata以'\t'分隔
        final String[] split = CommonUtils.bString(Arrays.copyOfRange(original, 20, original.length), chst).split("\t");
        if (split.length > 0) {
            this.id = split[0];
        }
        if (split.length > 1) {
            this.pid = split[1];
        }
        if (split.length > 2) {
            this.ver = split[2];
        }
        if (split.length > 3) {
            this.intz = split[3];
        }
        if (split.length > 4) {
            this.comp = split[4];
        }
        if (split.length > 5) {
            this.user = split[5];
        }
        if (split.length > 6) {
            this.is64 = split[6];
        }
        if (split.length > 7) {
            this.barch = ("1".equals(split[7]) ? "x64" : "x86");
        }
        if (split.length > 8) {
            this.port = split[8];
        }
        this.ext = ext;
        this.chst = chst;
        // 检验metadata数据是否合法
        this.sane = this.sanity();
```

合法性校验：

`common.BeaconEntry#_sanity(final LinkedList list)`

```java
if (!CommonUtils.isNumber(this.id)) {
     list.add("id '" + this.id + "' is not a number");
     this.id = "0";
 }
 if (!"".equals(this.intz) && !CommonUtils.isIP(this.intz) && !CommonUtils.isIPv6(this.intz) && !"unknown".equals(this.intz)) {
     list.add("internal address '" + this.intz + "' is not an address");
     this.intz = "";
 }
 if (!this.checkExt(this.ext)) {
     list.add("external address '" + this.ext + "' is not an address");
     this.ext = "";
 }
 if (!"".equals(this.pid) && !CommonUtils.isNumber(this.pid)) {
     list.add("pid '" + this.pid + "' is not a number");
     this.pid = "0";
 }
 if (!"".equals(this.port) && !CommonUtils.isNumber(this.port)) {
     list.add("port '" + this.port + "' is not a number");
     this.port = "";
 }
 if (!"".equals(this.is64) && !CommonUtils.isNumber(this.is64)) {
     list.add("is64 '" + this.is64 + "' is not a number");
     this.is64 = "";
 }
 if (this.comp != null && this.comp.length() > 64) {
     list.add("comp '" + this.comp + "' is too long. Truncating");
     this.comp = this.comp.substring(0, 63);
 }
 if (this.user != null && this.user.length() > 64) {
     list.add("user '" + this.user + "' is too long. Truncating");
     this.user = this.user.substring(0, 63);
 }
 if (list.size() > 0) {
     final Iterator<Object> iterator = list.iterator();
     CommonUtils.print_error("Beacon entry did not validate");
     while (iterator.hasNext()) {
         System.out.println("\t" + iterator.next());
     }
     return false;
 }
 return true;
```

