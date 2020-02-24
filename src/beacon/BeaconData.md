# overview

`beacon.BeaconData`实现了下发beacon任务进任务队列的相关逻辑

属性字段如下：

```java
    // beacon出口的通信类型
    public static final int MODE_HTTP = 0;
    public static final int MODE_DNS = 1;
    public static final int MODE_DNS_TXT = 2;
    public static final int MODE_DNS6 = 3;
    // Map<String, LinkedList> 包含了每个beacon对应的task队列
    // @key: beacon id
    // @val: task队列，链表类型
    protected Map queues;
	// Map<String, int> 包含了beacon对应的通信出口类型
    protected Map modes;
	// 存放有task的beacon的id
    protected Set tasked;
    // 用来遏制trial版使用的值
    protected boolean shouldPad;
    // 啥时候遏制trial版使用
    protected long when;
```

由于该分析是反编译cobaltstrike3.14，所以现在看来未免有些落伍了，因为cobaltstrike 4.0已经取消了trial版，上述字段也应该会删掉这些无用的东西了= =

# 分析

## 下发task

`beacon.BeaconData#task`是用来将build好的二进制的task数据放入队列中，下一次beacon callback时，就会发送出去。

```java
    public void task(final String bid, final byte[] array) {
        synchronized (this) {
            // 获取对应队列
            final List queue = this.getQueue(bid);
            // 如果这是trial版/检测出crack版，并且当前时间大于teamserver启动时间+1800000ms，即30分钟
            if (this.shouldPad && System.currentTimeMillis() > this.when) {
                final CommandBuilder commandBuilder = new CommandBuilder();
                // 3 == COMMAND_DIE,也就是结束beacon
                commandBuilder.setCommand(3);
                commandBuilder.addString(array);
                // 添加一个exit任务
                queue.add(commandBuilder.build());
            }
            else {
                // 直接添加任务
                queue.add(array);
            }
            // 将bid添加进有task的beacon id的set中
            this.tasked.add(bid);
        }
    }
```



## 导出task

`beacon.BeaconData#dump`

```java
public byte[] dump(final String bid, final int maxSize) {
    synchronized (this) {
        int total = 0;
        // 获取该beacon的task列表
        final List queue = this.getQueue(bid);
        if (queue.size() == 0) {
            return new byte[0];
        }
        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(8192);
        final Iterator<byte[]> iterator = queue.iterator();
        // 循环获取列表里的task
        while (iterator.hasNext()) {
            final byte[] b = iterator.next();
            // 加上这个task的大小不会超过最大大小
            if (total + b.length < maxSize) {
                // 写入流中
                byteArrayOutputStream.write(b, 0, b.length);
                // 从列表中去掉这个task
                iterator.remove();
                total += b.length;
            }
            else {
                // 加上这个task大小大于等于maxSize时，并且该task大小不大于maxSize
                if (b.length < maxSize) {
                    CommonUtils.print_warn("Chunking tasks for " + bid + "! " + b.length + " + " + total + " past threshold. " + queue.size() + " task(s) on hold until next checkin.");
                    break;
                }
                // task长度过大直接删掉这个task
                CommonUtils.print_error("Woah! Task " + b.length + " for " + bid + " is beyond our limit. Dropping it");
                iterator.remove();
            }
        }
        return byteArrayOutputStream.toByteArray();
    }
}

```



## 过时的trial分析

上面的`shouldPad`实际上就是下面的方法的判断

`beacon.BeaconC2#isPaddingRequired`

```java
protected boolean isPaddingRequired() {
     boolean b = false;
     try {
         final ZipFile zipFile = new ZipFile(this.appd);
         final Enumeration<? extends ZipEntry> entries = zipFile.entries();
         while (entries.hasMoreElements()) {
             final ZipEntry zipEntry = (ZipEntry)entries.nextElement();
             final long checksum8 = CommonUtils.checksum8(zipEntry.getName());
             final long n = zipEntry.getName().length();
             // resources/authkey.pub 是否被修改
             if (checksum8 == 75L && n == 21L) {
                 if (zipEntry.getCrc() == 1661186542L || zipEntry.getCrc() == 1309838793L) {
                     continue;
                 }
                 b = true;
             }
             // 检测common/License.class是否被修改
             else if (checksum8 == 144L && n == 20L) {
                 if (zipEntry.getCrc() == 1701567278L || zipEntry.getCrc() == 3030496089L) {
                     continue;
                 }
                 b = true;
             }
             else {
                 // 检测common/Authoriaztion.class是否被修改
                 if (checksum8 != 62L || n != 26L || zipEntry.getCrc() == 2913634760L || zipEntry.getCrc() == 376142471L) {
                     continue;
                 }
                 b = true;
             }
         }
         zipFile.close();
     }
     catch (Throwable t) {}
     return b;
 }
```

当判断了这三个文件被修改后，shouldPad就会为true了，进而引起了下发任务的逻辑变动。