# Overview

对称加密使用的是`AES128`，加密模式为`CBC`，iv为固定的`abcdefghijklmnop`，padding为自己实现的padding。数据包校验使用`HMACSHA256`。

当一段明文要加密时，会先增加一些信息：

```
| current time | plaintext length | plaintext | 'a' * padding_len |
```

其中current time是为了防止重放攻击，当一个密文被接收时，解密后会查询这个时间是否`<=`对应`Session`的计时器，如果小于等于，判断为重放，直接drop。

然后将最终的数据作为明文加密，然后在末尾加上HMAC：

```
| cipher text | MAC of cipher text |
```



一些`BaseSecurity`相关的字段信息可以参考`src/BeaconC2.md`的`加密`部分。

# 分析

## encrypt

`dns.BaseSecurity#encrypt`

```java
public byte[] encrypt(final String bid, final byte[] b) {
     try {
         // 之前是否注册了key
         if (!this.isReady(bid)) {
             CommonUtils.print_error("encrypt: No session for '" + bid + "'");
             return new byte[0];
         }
         final ByteArrayOutputStream out = new ByteArrayOutputStream(b.length + 1024);
         final DataOutputStream dataOutputStream = new DataOutputStream(out);
         final SecretKey key = this.getKey(bid);
         final SecretKey hashKey = this.getHashKey(bid);
         out.reset();
         // 大端序先写入当前的时间，单位为秒
         dataOutputStream.writeInt((int)(System.currentTimeMillis() / 1000L));
         // 大端序写入明文长度
         dataOutputStream.writeInt(b.length);
         // 写入明文
         dataOutputStream.write(b, 0, b.length);
         // padding至长度为16的整数，因为是AES128-CBC模式
         this.pad(out);
         byte[] do_encrypt = null;
         synchronized (this.in) {
             // 这个被QuickSecurity继承后实际上就是调用了Cipher.init和Cipher.doFinal加密
             do_encrypt = this.do_encrypt(key, out.toByteArray());
         }
         byte[] doFinal = null;
         // 生成密文的消息验证码
         synchronized (this.mac) {
             this.mac.init(hashKey);
             doFinal = this.mac.doFinal(do_encrypt);
         }
         final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
         // 先写入密文
         byteArrayOutputStream.write(do_encrypt);
         // 再写入HMAC
         byteArrayOutputStream.write(doFinal, 0, 16);
         return byteArrayOutputStream.toByteArray();
// ...
```

## decrypt

`dns.BaseSecurity#decrypt`

```java
public byte[] decrypt(final String s, final byte[] ciphertext) {
    try {
        // 之前是否注册过key
        if (!this.isReady(s)) {
            CommonUtils.print_error("decrypt: No session for '" + s + "'");
            return new byte[0];
        }
        final Session session = this.getSession(s);
        final SecretKey key = this.getKey(s);
        final SecretKey hashKey = this.getHashKey(s);
        // 获取HMAC
        final byte[] copyOfRange = Arrays.copyOfRange(ciphertext, 0, ciphertext.length - 16);
        // 获取密文
        final byte[] copyOfRange2 = Arrays.copyOfRange(ciphertext, ciphertext.length - 16, ciphertext.length);
        byte[] doFinal = null;
        synchronized (this.mac) {
            this.mac.init(hashKey);
            doFinal = this.mac.doFinal(copyOfRange);
        }
        // 判断HMAC是否正确
        if (!MessageDigest.isEqual(copyOfRange2, Arrays.copyOfRange(doFinal, 0, 16))) {
            CommonUtils.print_error("[Session Security] Bad HMAC on " + ciphertext.length + " byte message from Beacon " + s);
            return new byte[0];
        }
        byte[] do_decrypt = null;
        synchronized (this.out) {
            // 解密
            do_decrypt = this.do_decrypt(key, copyOfRange);
        }
        final DataInputStream dataInputStream = new DataInputStream(new ByteArrayInputStream(do_decrypt));
        // 获取这个包的创建时间
        final int int1 = dataInputStream.readInt();
        // 判断重放
        if (int1 <= session.counter) {
            CommonUtils.print_error("[Session Security] Bad counter (replay attack?) " + int1 + " <= " + session.counter + " message from Beacon " + s);
            return new byte[0];
        }
        // 获取数据长度
        final int int2 = dataInputStream.readInt();
        if (int2 < 0 || int2 > ciphertext.length) {
            CommonUtils.print_error("[Session Security] Impossible message length: " + int2 + " from Beacon " + s);
            return new byte[0];
        }
        final byte[] b = new byte[int2];
        dataInputStream.readFully(b, 0, int2);
        // 更新判断重放的计时器
        session.counter = int1;
        return b;
```

