# src

## c2profile

```
c2profile/
├── Checkers.java
├── Lint.java
├── LintURI.java
├── Loader.java
├── MalleableHook.java          负责调用Program转换和内部MyHook接口serve方法
├── MalleableStager.java
├── Preview.java
├── Profile.java
├── Program.java                具体的c2profile转换逻辑
└── SmartBuffer.java


```

## cloudstrike

```
cloudstrike/
├── CaptureContent.java
├── Hook.java
├── Keylogger.java
├── NanoHTTPD.java               修改版NanoHTTPD
├── ResponseFilter.java
├── Response.java
├── ServeApplet.java
├── ServeFile.java
├── StaticContent.java
├── WebServer.java				继承NanoHTTPD，真正的http server逻辑在这里
└── WebService.java              接口
```

## server

```
server
├── Beacons.java
├── BrowserPivotCalls.java
├── DataCalls.java
├── DownloadCalls.java
├── KeyloggerHandler.java
├── Listeners.java
├── ManageUser.java
├── PendingRequest.java
├── PersistentData.java
├── Phisher.java
├── ProfileEdits.java
├── ProfileHandler.java
├── Resources.java
├── ServerBus.java
├── ServerHook.java
├── ServerUtils.java
├── TeamServer.java
├── TestCall.java
├── VPN.java
├── WebCalls.java                 实现了cloudstrike.WebServer.WebListener
└── WebsiteCloneTool.java
```



## beacon

```
beacon/
├── BeaconC2.java                 负责处理与beacon交互的数据的编码解码工作，具体的c2协议实现在这里
├── BeaconCharsets.java
├── BeaconCommands.java
├── BeaconData.java               负责beacon的task队列相关逻辑
├── BeaconDNS.java                实现了beacon dns listener相关逻辑
├── BeaconDownloads.java
├── BeaconErrors.java
├── BeaconExploits.java
├── BeaconHTTP.java               实现了beacon http listener相关逻辑
├── BeaconParts.java
├── BeaconPipes.java              管理smb beacon的连接信息，parent-children关系
├── BeaconPivot.java
├── BeaconSetup.java              负责新的listener的初始化工作
├── BeaconSocks.java
├── BeaconTabCompletion.java
├── CheckinListener.java
├── CommandBuilder.java           负责构造c2数据包
├── dns
│   ├── CacheManager.java
│   ├── ConversationManager.java
│   ├── RecvConversation.java
│   ├── SendConversationAAAA.java
│   ├── SendConversationA.java
│   ├── SendConversation.java
│   └── SendConversationTXT.java
├── EncodedCommandBuilder.java
├── exploits
│   ├── BypassUAC.java
│   ├── BypassUACToken.java
│   └── cve_2014_4113.java
├── Job.java                       定义了c2协议中返回结果的类型
├── jobs
│   ├── BypassUACJob.java
│   ├── BypassUACTokenJob.java
│   ├── DllSpawnJob.java
│   ├── ElevateJob.java
│   ├── ExecuteAssemblyJob.java
│   ├── HashdumpJob.java
│   ├── KeyloggerJob.java
│   ├── MimikatzJob.java
│   ├── MimikatzJobSmall.java
│   ├── NetViewJob.java
│   ├── PortScannerJob.java
│   ├── PowerShellJob.java
│   └── ScreenshotJob.java
├── JobSimple.java
├── pivots
│   ├── PortForwardPivot.java
│   ├── ReversePortForwardPivot.java
│   └── SOCKSPivot.java
├── PowerShellTasks.java
├── Registry.java
├── SecureShellCommands.java
├── SecureShellTabCompletion.java
├── Settings.java
├── setup
│   ├── BrowserPivot.java
│   ├── ProcessInject.java
│   └── SSHAgent.java
├── TaskBeaconCallback.java
├── TaskBeacon.java
├── TaskBeaconStaging.java
└── Tasks.java                         定义了c2协议的command类型

```

