# overview

package beacon.BeaconSetup拥有以下字段

```java
    protected WebCalls web;
    protected DNSServer dns;
    protected Profile c2profile;
    protected BeaconC2 handlers;
    protected BeaconData data;
    protected String error;
    protected Resources resources;
    protected Map c2info;
    protected MalleablePE pe;
```

还有静态字段：

```java
    public static final int SETTING_PROTOCOL = 1;
    public static final int SETTING_PORT = 2;
    public static final int SETTING_SLEEPTIME = 3;
    public static final int SETTING_MAXGET = 4;
    public static final int SETTING_JITTER = 5;
    public static final int SETTING_MAXDNS = 6;
    public static final int SETTING_PUBKEY = 7;
    public static final int SETTING_DOMAINS = 8;
    public static final int SETTING_USERAGENT = 9;
    public static final int SETTING_SUBMITURI = 10;
    public static final int SETTING_C2_RECOVER = 11;
    public static final int SETTING_C2_REQUEST = 12;
    public static final int SETTING_C2_POSTREQ = 13;
    public static final int SETTING_SPAWNTO = 14;
    public static final int SETTING_PIPENAME = 15;
    public static final int DEPRECATED_SETTING_KILLDATE_YEAR = 16;
    public static final int DEPRECATED_SETTING_KILLDATE_MONTH = 17;
    public static final int DEPRECATED_SETTING_KILLDATE_DAY = 18;
    public static final int SETTING_DNS_IDLE = 19;
    public static final int SETTING_DNS_SLEEP = 20;
    public static final int SETTING_SSH_HOST = 21;
    public static final int SETTING_SSH_PORT = 22;
    public static final int SETTING_SSH_USERNAME = 23;
    public static final int SETTING_SSH_PASSWORD = 24;
    public static final int SETTING_SSH_KEY = 25;
    public static final int SETTING_C2_VERB_GET = 26;
    public static final int SETTING_C2_VERB_POST = 27;
    public static final int SETTING_C2_CHUNK_POST = 28;
    public static final int SETTING_SPAWNTO_X86 = 29;
    public static final int SETTING_SPAWNTO_X64 = 30;
    public static final int SETTING_CRYPTO_SCHEME = 31;
    public static final int SETTING_PROXY_CONFIG = 32;
    public static final int SETTING_PROXY_USER = 33;
    public static final int SETTING_PROXY_PASSWORD = 34;
    public static final int SETTING_PROXY_BEHAVIOR = 35;
    public static final int DEPRECATED_SETTING_INJECT_OPTIONS = 36;
    public static final int SETTING_WATERMARK = 37;
    public static final int SETTING_CLEANUP = 38;
    public static final int SETTING_CFG_CAUTION = 39;
    public static final int SETTING_KILLDATE = 40;
    public static final int SETTING_GARGLE_NOOK = 41;
    public static final int SETTING_GARGLE_SECTIONS = 42;
    public static final int SETTING_PROCINJ_PERMS_I = 43;
    public static final int SETTING_PROCINJ_PERMS = 44;
    public static final int SETTING_PROCINJ_MINALLOC = 45;
    public static final int SETTING_PROCINJ_TRANSFORM_X86 = 46;
    public static final int SETTING_PROCINJ_TRANSFORM_X64 = 47;
    public static final int DEPRECATED_SETTING_PROCINJ_ALLOWED = 48;
    public static final int SETTING_BINDHOST = 49;
    public static final int SETTING_HTTP_NO_COOKIES = 50;
    public static final int SETTING_PROCINJ_EXECUTE = 51;
    public static final int SETTING_PROCINJ_ALLOCATOR = 52;
    public static final int SETTING_PROCINJ_STUB = 53;
```

静态字段定义了beacon的stage，即beacon核心逻辑Dll的配置。

初始化过程：

```java
    public BeaconSetup(final Resources resources) {
        this.web = null;
        this.dns = null;
        this.c2profile = null;
        this.handlers = null;
        this.data = new BeaconData();
        this.error = "";
        this.c2info = null;
        this.pe = null;
        this.resources = resources;
        this.web = ServerUtils.getWebCalls(resources);
        this.c2profile = ServerUtils.getProfile(resources);
        this.pe = new MalleablePE(this.c2profile);
        this.handlers = new BeaconC2(this.c2profile, this.data, resources);
    }
```

