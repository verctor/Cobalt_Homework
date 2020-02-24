[TOC]

# overview

这个是关于cobaltstrike3.13的分析，之前做的，不是3.14哦

# tasks flow分析

---------

## 从client到teamserver

在beacon的interactive console输入命令后会直接用下面方法进行处理

aggressor/windows/BeaconConsole.java:

```java
public void actionPerformed(final ActionEvent ev) { //分发具体命令
	final String text = ev.getActionCommand().trim();
    ((JTextField)ev.getSource()).setText("");
    final CommandParser parser = new CommandParser(text);
    //...
    this.master.input(text); //服务端输出到log文件
    if (parser.is("argue")) { //以argue为例
        if (!this.isVistaAndLater()) {
            parser.error("Target is not Windows Vista or later");
        }
        //假设输入 argue powershell IEX "whomai && ls"
        else if (parser.verify("AZ") || parser.reset()) { //根据格式“AZ”进行命令的解析
            final String args = parser.popString(); //Z表示余下的所有字符串
            final String command2 = parser.popString(); //A表示一个不含空格的字符串，这里就是powershell
            this.master.SpoofArgsAdd(command2, args); //调用TaskBeacon的具体方法
        }
        else if (parser.verify("A") || parser.reset()) {
            final String command = parser.popString();
            this.master.SpoofArgsRemove(command);
        }
        else {
            this.master.SpoofArgsList();
        }
    }
    //...
}
```

首先要知道beacon c&c命令的定义

```java
//beacon/Tasks.java:
public class Tasks
{
    public static final int COMMAND_SPAWN = 1;
    public static final int COMMAND_SHELL = 2;
    public static final int COMMAND_DIE = 3;
    public static final int COMMAND_SLEEP = 4;
    public static final int COMMAND_CD = 5;
    public static final int COMMAND_KEYLOG_START = 6;
    public static final int COMMAND_KEYLOG_STOP = 7;
    public static final int COMMAND_INJECT_PID = 9;
    public static final int COMMAND_INJECT_PING = 18;
    public static final int COMMAND_UPLOAD = 10;
    public static final int COMMAND_SPAWN_PROC_X86 = 13;
    public static final int COMMAND_JOB_REGISTER = 40;
    public static final int COMMAND_INJECTX64_PID = 43;
    public static final int COMMAND_SPAWNX64 = 44;
    public static final int COMMAND_JOB_REGISTER_IMPERSONATE = 62;
    public static final int COMMAND_SPAWN_POWERSHELLX86 = 63;
    public static final int COMMAND_SPAWN_POWERSHELLX64 = 64;
    public static final int COMMAND_INJECT_POWERSHELLX86_PID = 65;
    public static final int COMMAND_INJECT_POWERSHELLX64_PID = 66;
    public static final int COMMAND_UPLOAD_CONTINUE = 67;
    public static final int COMMAND_PIPE_OPEN_EXPLICIT = 68;
    public static final int COMMAND_SPAWN_PROC_X64 = 69;
    public static final int COMMAND_JOB_SPAWN_X86 = 70;
    public static final int COMMAND_JOB_SPAWN_X64 = 71;
    public static final int COMMAND_SETENV = 72;
    public static final int COMMAND_FILE_COPY = 73;
    public static final int COMMAND_FILE_MOVE = 74;
    public static final int COMMAND_PPID = 75;
    public static final int COMMAND_RUN_UNDER_PID = 76;
    public static final int COMMAND_GETPRIVS = 77;
    public static final int COMMAND_EXECUTE_JOB = 78;
    public static final int COMMAND_PSH_HOST_TCP = 79;
    public static final int COMMAND_DLL_LOAD = 80;
    public static final int COMMAND_REG_QUERY = 81;
    public static final int COMMAND_LSOCKET_TCPPIVOT = 82;
    public static final int COMMAND_ARGUE_ADD = 83;
    public static final int COMMAND_ARGUE_REMOVE = 84;
    public static final int COMMAND_ARGUE_LIST = 85;
    public static final int COMMAND_TCP_CONNECT = 86;
    public static final int COMMAND_JOB_SPAWN_TOKEN_X86 = 87;
    public static final int COMMAND_JOB_SPAWN_TOKEN_X64 = 88;
    public static final int COMMAND_SPAWN_TOKEN_X86 = 89;
    public static final int COMMAND_SPAWN_TOKEN_X64 = 90;
    public static final int COMMAND_INJECTX64_PING = 91;
    
    public static final long max() {
        return 1048576L;
    }
}
```

beacon/TaskBeacon.java：

这里的this.builder是beacon/EncodedCommandBuilder.java里的类，但是这个类只是在`CommandBuilder`的基础上会对字符串根据目标上的字符集进行编码，其次java的字节序问题没搞懂= =

```java
//...
public void SpoofArgsAdd(final String command, final String fakeargs) {
    final String result = command + " " + fakeargs;
    this.builder.setCommand(83); //即COMMAND_ARGUE_ADD
    this.builder.addLengthAndString(command); //向buffer写入 4字节的command的长度，再写入command
    this.builder.addLengthAndString(command + " " + fakeargs);
    final byte[] task = this.builder.build(); //构造发送给目标的cc字节数组
    for (int x = 0; x < this.bids.length; ++x) {
        this.log_task(this.bids[x], "Tasked beacon to spoof '" + command + "' as '" + fakeargs + "'", "T1059, T1093, T1106");
        this.conn.call("beacons.task", CommonUtils.args(this.bids[x], task)); //args方法将参数打包成object[]
    }
}
//...
```

CommandBuilder：

```java
//...    
public byte[] build() {
    try {
        this.output.flush();
        final byte[] args = this.backing.toByteArray(); //将builder的buffer转换成字节数组
        this.backing.reset();
        this.output.writeInt(this.command); //写入4字节的cc命令，大端序
        this.output.writeInt(args.length); //写入args的长度，大端序
        if (args.length > 0) {
            this.output.write(args, 0, args.length); //写入args
        }
        this.output.flush();
        final byte[] result = this.backing.toByteArray();
        this.backing.reset();
        return result; //返回上述组成的字节数组
    }
    catch (IOException ioex) {
        MudgeSanity.logException("command builder", ioex, false);
        return new byte[0];
    }
}
...
```

之后client会向服务器发送请求，由服务器向beacon目标发送cc命令

common/TeamQueue.java：

```java
    public void call(final String name, final Object[] args, final Callback c) {
        if (c == null) {
            final Request r = new Request(name, args, 0L); //new 一个Request对象
            this.writer.addRequest(r); //添加request对象到writer的队列里
        }
        else {
            synchronized (this.callbacks) {
                ++this.reqno;
                this.callbacks.put(new Long(this.reqno), c);
                final Request r2 = new Request(name, args, this.reqno);
                this.writer.addRequest(r2);
            }
        }
    }
//...

//TeamWriter
//...
        @Override
        public void run() {
            while (TeamQueue.this.socket.isConnected()) {
                final Request next = this.grabRequest(); //pop 链表第一个节点
                if (next != null) {
                    TeamQueue.this.socket.writeObject(next); //发送Request对象
                    Thread.yield();
                }
                else {
                    try {
                        Thread.sleep(25L);
                    }
                    catch (InterruptedException iex) {
                        MudgeSanity.logException("teamwriter sleep", iex, false);
                    }
                }
            }
        }
```

common/TeamSocket.java：

```java
//...
    public void writeObject(final Object data) {
        if (!this.isConnected()) {
            return;
        }
        try {
            synchronized (this.client) {
                if (this.bout == null) {
                    this.bout = new BufferedOutputStream(this.client.getOutputStream(), 262144);
                }
                final ObjectOutputStream out = new ObjectOutputStream(this.bout);
                out.writeUnshared(data); //实际上就是序列化Request对象，发送出去
                out.flush(); //清空缓存，发送数据
            }
        }
        catch (IOException ioex) {
            MudgeSanity.logException("client (" + this.from + ") write", ioex, true);
            this.close();
        }
        catch (Exception ex) {
            MudgeSanity.logException("client (" + this.from + ") write", ex, false);
            this.close();
        }
    }
//...
```

## 从teamserver到beacon

teamserver负责控制与client交互的是ManageUser类

server/TeamServer.java:

```java
           //...
           while (true) {
                server.acceptAndAuthenticate(this.pass, new PostAuthentication() {
                    @Override
                    public void clientAuthenticated(final Socket client) {
                        try {
                            client.setSoTimeout(0);
                            final TeamSocket plebe = new TeamSocket(client);
                            new Thread(new ManageUser(plebe, TeamServer.this.resources, TeamServer.this.calls), "Manage: unauth'd user").start();
                        }
                        catch (Exception ex) {
                            MudgeSanity.logException("Start client thread", ex, false);
                        }
                    }
                });
            }
            //...
```

server/ManageUser.java:

```java
//...
public void process(final Request r) throws Exception {
//检查Request的call是否是其他字段的if分支
    
    else if (this.calls.containsKey(r.getCall())) { //teamserver的call是否有request里的call字段对应的call，命令通过上面可以知道，这里的call是`beacons.task`，刚好来到这个分支
    	final ServerHook callme = this.calls.get(r.getCall());
    	callme.call(r, this); //有就调用
	}
//...
@Override
public void run() {
    try {
        this.mine = Thread.currentThread();
        //当连接未关闭时，从client接受Request对象，传参给process对象
        while (this.client.isConnected()) {
            final Request r = (Request)this.client.readObject();
            if (r != null) {
                this.process(r);
            }
        }
    }
    catch (Exception ex) {
        MudgeSanity.logException("manage user", ex, false);
        this.client.close();
    }
    if (this.authenticated) {
        this.resources.deregister(this.nickname, this);
        this.resources.broadcast("eventlog", LoggedEvent.Quit(this.nickname));
    }
}
//...
```

再回到server/TeamServer.java:

```java
    //...
	public void go() {
        try {
            //将一系列的ServerHook对象注册到this.calls里
            new ProfileEdits(this.c2profile);
            this.c2profile.addParameter(".watermark", this.auth.getWatermark());
            (this.resources = new Resources(this.calls)).put("c2profile", this.c2profile);
            this.resources.put("localip", this.host);
            this.resources.put("password", this.pass);
            new TestCall().register(this.calls);
            final WebCalls web = new WebCalls(this.resources);
            web.register(this.calls);
            this.resources.put("webcalls", web);
            new Listeners(this.resources).register(this.calls);
            new Beacons(this.resources).register(this.calls);
            new Phisher(this.resources).register(this.calls);
            new VPN(this.resources).register(this.calls);
            new BrowserPivotCalls(this.resources).register(this.calls);
            new DownloadCalls(this.resources).register(this.calls);
            final Iterator i = Keys.getDataModelIterator();
            while (i.hasNext()) {
                new DataCalls(this.resources, i.next()).register(this.calls);
            }
    //...
```

可以知道this.calls里beacons.task对应的是server/Beacons.java里的类实例

server/Beacons.java：

```java
    public Beacons(final Resources r) {
        this.beacons = new HashMap();
        this.data = null;
        this.socks = null;
        this.cmdlets = new HashMap();
        this.setup = null;
        this.notes = new HashMap();
        this.empty = new HashSet();
        this.initial = new LinkedList();
        this.resources = r;
        this.web = ServerUtils.getWebCalls(r);
        Timers.getTimers().every(1000L, "beacons", this);
        r.put("beacons", this);
        this.setup = new BeaconSetup(this.resources);
        this.setup.getHandlers().setCheckinListener(this);
        this.data = this.setup.getData(); //从BeaconSetup的实例中获取BeaconData实例
        this.socks = this.setup.getSocks();
        this.resources.broadcast("cmdlets", new HashMap(), true);
    }
	//...
	@Override
    public void call(final Request r, final ManageUser client) {
        //...
        else if (r.is("beacons.task", 2)) {
            final String id = r.arg(0) + ""; //这个就是bid
            final byte[] task = (byte[])r.arg(1); //client build好的字节数组，表示了要发送的命令
            this.data.task(id, task);
        }
        //...
```

beacon/BeaconData.java：

```java
//...
    public void task(final String bid, final byte[] data) {
        synchronized (this) {
            final List queue = this.getQueue(bid); //bid如果有对应的队列就直接返回该队列的引用，否则新建队列，并添加到实例的队列HashMap里
            queue.add(data); //队列append一个待发送的数据
            this.tasked.add(bid); //使用Set表示需要发送task的bid集合
        }
    }
//...
```

至此，要发送的task都被封装好了，就等其他的代码调用这个来发送它，因此为了搞清楚如何发送这个数据，需要分析其他部分的代码。