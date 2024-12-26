# Spring4Shell 漏洞复现及分析


## 背景

2022 年 3 月 31 日，Spring Framework for Java 中的漏洞被公开披露，现已被给予编号 CVE-2022-22965。

Spring 框架是 Java 中使用最广泛的轻量级开源框架。在 Java Development Kit (JDK) 9.0 或更高版本中，远程攻击者可以通过框架的参数绑定特性获取 AccessLogValve 对象，并使用恶意字段值触发管道机制，并在某些条件下写入任意路径的文件。该漏洞现已被修补。

spring 官方公告：
<https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement>

## 前置知识

* JavaBean
* JavaBean 内省
* Spring CachedIntrospectionResults
* spring 参数绑定

### JavaBean

JavaBean 本质上就是一个 Java 类，但是其是一种特殊的、可重用的类。

其是符合一定规范编写的 Java 类，不是一种技术，而是一种规范。大家针对这种规范，总结了很多开发技巧、工具函数。符合这种规范的类，可以被重用。

编写 JavaBean 必须满足以下几点要求：

1. 这个类必须具有一个公共的 (public) 无参构造函数；
2. 所有属性私有化 (private)；
3. 私有化的属性必须通过 public 类型的方法 (getter 和 setter) 暴露给其他程序，并且方法的命名也必须遵循一定的命名规范。
4. 这个类应是可序列化的。（比如可以实现 Serializable 接口，用于实现 bean 的持久性）

``` java
package player;

public class PersonBean implements java.io.Serializable {

    // name 属性
    private String name = null;
    // deceased 属性
    private boolean deceased = false;

    // 无参构造函数
    public PersonBean() {
    }

    //name 的 getter 方法
    public String getName() {
        return name;
    }
    //name 的 setter 方法
    public void setName(final String value) {
        name = value;
    }
    // deceased 的 getter 方法
    // boolean 类型的特殊 getter
    public boolean isDeceased() {
        return deceased;
    }
    // deceased 的 setter 方法
    public void setDeceased(final boolean value) {
        deceased = value;
    }
}
```

### JavaBean 内省

#### 基本概念

内省 (IntroSpector): 计算机程序在运行时 (Runtime) 检查对象 (Object) 类型的一种能力，通常也可以称作运行时类型检查

Java 官方对 JavaBean 内省的定义
> At runtime and in the builder environment we need to be able to figure out which properties, events, and methods a Java Bean supports. We call this process introspection.

从 Java Bean 的角度来看，这里的对象就是 Bean 对象，主要关注点是属性、方法和事件等，也就是说在运行时可以获取相应的信息进行一些处理，这就是 JavaBean 的内省机制。

上述描述和反射很接近，反射是获取一个对象所属的类，并通过 Class 调用类内的属性和方法，和内省机制很接近。

#### 和反射的区别

首先明确，内省其实就是对反射的封装

> By default we will use a low level reflection mechanism to study the methods supported by a target bean and then apply simple design patterns to deduce from those methods what properties, events, and public methods are supported.

* 反射：在运行状态把 Java 类中的各种成分映射成相应的 Java 类 (Method, Class 等），可以动态的获取所有的属性以及动态调用任意一个方法，强调的是运行状态
* 内省：Java 语言针对 Bean 类属性、事件的一种缺省处理方法，并且内省机制是通过反射来实现的。返回的 BeanInfo 用来暴露一个 Bean 的属性、方法和事件，以后我们就可以操纵该 JavaBean 的属性

#### 源码分析详解

##### PropertyDescriptor

属性描述符，该类实现了对 JavaBean 的某一属性的所有描述
主要方法包括：

1. getPropertyType()，获得属性的 Class 对象；
2. getReadMethod()，获得用于读取属性值的方法；
3. getWriteMethod()，获得用于写入属性值的方法；
4. hashCode()，获取对象的哈希值；
5. setReadMethod(Method readMethod)，设置用于读取属性值的方法；
6. setWriteMethod(Method writeMethod)，设置用于写入属性值的方法。

``` java
public class User {
    
    private String name;

    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }
    
    @Override
    public String toString() {
        return "User{" +
                "name='" + name + '\'' +
                '}';
    }
}

public static void main (String[] args) throws Exception {
    
    // 创建并输出 User 对象的值
    User user = new User();
    System.out.println( user.toString );

    // 创建一个 User.name 的属性描述符
    PropertyDescriptor propertyDescriptor = new PropertyDescriptor( "name", User.class );

    // 获得并调用 User.name 的读方法，也就是 getter --> User.getname()
    Method readMethod = propertyDescriptor.getReadMethod();
    System.out.println( readMethod.invoke( user ) );

    // 获得并调用 User.name 的写方法，也就是 setter --> User.setname()
    Method writeMethod = propertyDescriptor.getWriteMethod();
    writeMethod.invoke( user, "hello" );

    System.out.println( user.toString );
}
```

``` text
输出结果：
    User{name='null', aName='null'}
    null
    User{name='hello', aName='null'}
```

通过上述的例子，可以看出 PropertyDescriptor, 就是对属性反射的一种封装，方便操作对应 JavaBean 的属性，使用 PropertyDescriptor 其实就是利用反射对其 get 和 set 方法的操作而已。  

##### BeanInfo

BeanInfo 是一个接口，其常用的实现是 GenericBeanInfo

``` java
class GenericBeanInfo extends SimpleBeanInfo {
    // JavaBean 的描述符，持有类 Class 对象的引用
    private BeanDescriptor beanDescriptor;
    // JavaBean 的所有属性描述符
    private PropertyDescriptor[] properties;
    // JavaBean 的所有方法描述符
    private MethodDescriptor[] methods;
    ...
}
```

BeanInfo 就是对一个 JavaBean 类所有的属性、方法等反射操作封装后的集合体。

##### IntroSpector

介绍完了内省所需要的所有前置知识，最后说回最开始的内省机制。

Java 中提供了一套 API 用来访问某个属性的 getter/setter 方法。

* Introspector, 提供了 `getBeanInfo` 方法，可以拿到一个 JavaBean 的所有信息
* BeanInfo, 提供了  `getPropertyDescriptors` 方法和 `getMethodDescriptors` 方法可以拿到 javaBean 的字段信息列表和 getter 和 setter 方法信息列表
* PropertyDescriptors 可以根据字段直接获得该字段的 getter 和 setter 方法
* MethodDescriptors 可以获得方法的元信息，比如方法名，参数个数，参数字段类型等

通过 Introspector 获取一个类的 BeanInfo, 通过 BeanInfo 能够获取属性描述器、方法描述器、类 Class 对象，利用获取到的属性描述器，我们能够往一个该类实例中放入数据

``` java
public static void main(String[] args) throws Exception {
    BeanInfo beanInfo = Introspector.getBeanInfo( Customer.class );
    PropertyDescriptor[] propertyDescriptors = beanInfo.getPropertyDescriptors();
    MethodDescriptor[] methodDescriptors = beanInfo.getMethodDescriptors();
    BeanDescriptor beanDescriptor = beanInfo.getBeanDescriptor();
}
```

### Spring CachedIntrospectionResults

``` java
public final class CachedIntrospectionResults {

    /**
     * Map keyed by Class containing CachedIntrospectionResults, strongly held.
     * This variant is being used for cache-safe bean classes.
     */
    static final ConcurrentMap<Class<?>, CachedIntrospectionResults> strongClassCache =
            new ConcurrentHashMap<>(64);

    /**
     * Map keyed by Class containing CachedIntrospectionResults, softly held.
     * This variant is being used for non-cache-safe bean classes.
     */
    static final ConcurrentMap<Class<?>, CachedIntrospectionResults> softClassCache =
            new ConcurrentReferenceHashMap<>(64);

    static CachedIntrospectionResults forClass(Class<?> beanClass) throws BeansException {
        
        // 尝试在 strongClassCache 中获得
        CachedIntrospectionResults results = strongClassCache.get(beanClass);
        if (results != null) {
            return results;
        }

        // 获取不到的话在 softClassCache 中获取
        results = softClassCache.get(beanClass);
        if (results != null) {
            return results;
        }

        // 如果都没有获得 创建对象进行获取
        results = new CachedIntrospectionResults(beanClass);
        ConcurrentMap<Class<?>, CachedIntrospectionResults> classCacheToUse;

        if (ClassUtils.isCacheSafe(beanClass, CachedIntrospectionResults.class.getClassLoader()) ||
                isClassLoaderAccepted(beanClass.getClassLoader())) {
            classCacheToUse = strongClassCache;
        }
        else {
            if (logger.isDebugEnabled()) {
                logger.debug("Not strongly caching class [" + beanClass.getName() + "] because it is not cache-safe");
            }
            classCacheToUse = softClassCache;
        }

        // 缓存获得的结果
        CachedIntrospectionResults existing = classCacheToUse.putIfAbsent(beanClass, results);
        return (existing != null ? existing : results);
    }

}
```

`CachedIntrospectionResults`这个类是 Spring 提供的对类的内省机制使用的工具类，不同于`Introspector`之处在于，该类提供类内省机制时的数据缓存，即内省获得的`PropertyDescriptor`这些数据进行了缓存，之后通过全局变量 Map 提供了对内省机制获得的`BeanInfo`信息的缓存，从而可以方便通过 static 方法获取对应类的内省信息。

### spring 参数绑定

在 springMVC 中，接收页面提交的数据是通过方法形参来接收的。从客户端请求的 `key/value` 数据，经过参数绑定，将 `key/value` 数据绑定到 `controller` 方法的形参上，然后就可以在 `controller` 中使用该参数了。

eg:

JavaBean

``` java
package top.dre4merp;

public class User {
    private String name;
    private Integer age;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Integer getAge() {
        return age;
    }

    public void setAge(Integer age) {
        this.age = age;
    }

    @Override
    public String toString() {
        return "User{" +
                "name='" + name + '\'' +
                ", age=" + age +
                '}';
    }
}
```

Controller

``` java
package top.dre4merp;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class TestController {
    @RequestMapping(path = "/test")
    @ResponseBody
    public String Test(User u){
        return u.toString();
    }
}
```

结果

![20220402164705](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/20220402164705.png "20220402164705.png")

## 漏洞分析

### 漏洞点分析

Spring4Shell 的漏洞点就在对参数进行赋值的过程中

在`org.springframework.beans.AbstractPropertyAccessor#setPropertyValues(org.springframework.beans.PropertyValues, boolean, boolean)`这个函数中获取用户输入的参数并对 bean 对象进行赋值

![20220402170650](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/20220402170650.png "20220402170650.png")

在赋值的过程中需要获取到对应的参数对象的参数描述符，其中的`getCachedIntrospectionResults().getPropertyDescriptor(propertyName)`函数便是通过名字在前文提到的缓存中获取参数描述符

![20220402171358](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/20220402171358.png "20220402171358.png")

![20220402172103](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/20220402172103.png "20220402172103.png")

如上图，取到了缓存的`top.dre4merp.User`的属性描述符，其中包含了三个属性，其中的`name`和`age`没有任何问题，但是其中的`class`并不是我们设置的

查看一下`class`的具体属性值，可以看出其是一个指向`top.dre4merp.User`的`java.lang.Class`, 通过这个属性描述符可以进行反射调用。那这个`class`是从哪里来的呢，这就需要我们回到第一次缓存的时候查看。

![20220402173407](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/20220402173407.png "20220402173407.png")

下图中，红框以下的部分之前已经分析过，包括`forClass`。红框中的部分就是 spring 调用 java 本身的内省，也就是`IntroSpector`获得 BeanInfo

![20220402175047](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/20220402175047.png "20220402175047.png")

上图中出现了递归调用是因为`IntroSpector`会获取父类的 BeanInfo

![20220402175742](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/20220402175742.png "20220402175742.png")

之后在获得子类的 BeanInfo 时，会先将父类的`PropertyDescriptor`添加到子类的`PropertyDescriptors`中，所以理论上所有继承自`Object`的类都会获得`class`属性

![20220406152822](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/20220406152822.png "20220406152822.png")

### 利用分析

利用这个漏洞进行 RCE 的本质其实是对 tomcat 的配置进行**覆盖修改**，修改 tomcat 的日志位置到根目录，修改日志的后缀为 jsp，即上传了一个 shell.jsp。

以下为 POC 中关键的信息：

* pattern 为生成的 shell.jsp 中的内容
* suffix 为日志文件后缀名
* directory 为日志文件 (jsp) 放置的路径
* prefix 为日志文件前缀名
* fileDateFormat 为日志文件的输出格式

``` java
class.module.classLoader.resources.context.parent.pipeline.first.pattern=
&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp
&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT
&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell
&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=
```

在`org.springframework.beans#getPropertyAccessorForPropertyPath(String)`中递归寻找对应的属性访问器

![20220406160956](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/20220406160956.png "20220406160956.png")

最后在`org.springframework.beans#setPropertyValue(PropertyValue)`中设置由用户控制的值

![20220406160123](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/20220406160123.png "20220406160123.png")

### 利用条件

* 中间件为 Tomcat
  * 目前传出的 POC 中，均为利用 Tomcat 的日志进行 shell 的上传
  * 打包为 WAR 并部署在独立的 Tomcat 实例中；使用嵌入式 Servlet 容器或 Spring Boot 部署不受影响
  * Tomcat 有 spring-webmvc 或 spring-webflux 依赖
* jdk 版本 >= 9
  * 如下图，当初 Spring 修复了 CVE-2010-1622，修复方式是拦截 `Class.getClassLoader` 的访问。但是 Java9 新增了可以通过`Class.getModule`方法。通过`getModule`的结果可以调用`getClassloader`的方式继续访问更多对象的属性。

![20220406163847](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/20220406163847.png "20220406163847.png")

## 漏洞防护

### 官方修复建议

更新至最新版本。

### 临时防护方案

在WAF等网络防护设备上，根据实际部署业务的流量情况，实现对"class.\*","Class.\*",".class.\*","\*.Class.\*"等字符串的规则过滤，并在部署过滤规则后，对业务运行情况进行测试，避免产生额外影响

## 参考

<https://juejin.cn/post/6844904177156489229>  
<https://xiaomi-info.github.io/2020/03/16/java-beans-introspection/>  
<https://jasonkayzk.github.io/2020/03/02/Java%E7%9A%84%E5%86%85%E7%9C%81%E6%8A%80%E6%9C%AF/>  
<https://www.microsoft.com/security/blog/2022/04/04/springshell-rce-vulnerability-guidance-for-protecting-against-and-detecting-cve-2022-22965/>

