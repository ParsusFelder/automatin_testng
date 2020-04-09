package qa.infosec.testng.netsign.dataprovider.util;

import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.testng.Assert;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.util.*;

/**
 * 对文件进行操作
 * <p>Title: ParseFile</p>
 * <p>Description: </p>
 *
 * @author maxf
 * @date 2019年8月13日
 */
public class ParseFile {

    /**
     * 获取key对应的value值
     *
     * @param key      键值
     * @param confpath 配置文件路径，为null，使用默认路径
     * @return keyValue value值
     */
    public static String parseProperties(String key, String confpath) {
        if (confpath == null) {
            confpath = "../../data/conf/netsignconfig.properties";
        }
        Properties props = new Properties();
        try {
            InputStream in = new BufferedInputStream(new FileInputStream(confpath));
            props.load(in);
            String value = props.getProperty(key);
            // System.out.println(key+value);
            return value;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static Map<String, String> parseProperties(String confpath) {
        if (confpath == null) {
            confpath = "../../data/conf/netsignconfig.properties";
        }
        Properties prop = new Properties();
        Map<String, String> map = new LinkedHashMap<>();
        try {
            InputStream in = new BufferedInputStream(new FileInputStream(confpath));
            prop.load(in);
            Iterator<String> it = prop.stringPropertyNames().iterator();
            while (it.hasNext()) {
                String key = it.next();
                map.put(key, prop.getProperty(key));
            }
            in.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return map;
    }

    /**
     * 获取大文件数据
     *
     * @return byte[]
     */
    public static byte[] getFileData(String filepath) {
        byte[] bfiledata = null;

        try {
            // 读取大文件数据
            File dir = new File(filepath);
            File[] f = dir.listFiles();

            if (null == f || f.length == 0) {
                Assert.fail(filepath + "目录为空,无法读取文件");
            } else if (f.length > 1) {
                Assert.fail("目前不支持多个大文件签名");
            } else {
                FileInputStream fis = new FileInputStream(f[0]);
                bfiledata = new byte[fis.available()];
                fis.read(bfiledata);
                fis.close();
            }
        } catch (Exception e) {
            Assert.fail("读文件失败！：" + e.getMessage());
        }
        return bfiledata;
    }

    /**
     * 获取机构代码
     *
     * @param path
     * @return String[]
     */
    public static String[] parseBankCode(String path) {
        List<String> bankcode = new ArrayList<String>();
        try {
            File file = new File(path); //Text文件
            BufferedReader br = new BufferedReader(new FileReader(file));    //构造一个BufferedReader类来读取文件
            String s = null;
            while ((s = br.readLine()) != null) {    //使用readLine方法，一次读一行
                String[] str = s.split("[|]");
                if (str[3].indexOf("CN") != -1) {
                    bankcode.add(str[1]);
                }
            }
            br.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return bankcode.toArray(new String[bankcode.size()]);
    }

    /**
     * 获取机构代码
     *
     * @param path     detail.conf文件路径
     * @param certpath 证书路径
     * @param keyType  证书类型
     * @return
     */
    public static String[] getBankCode(String path, String certpath, String keyType) {
        String[] dn = ParseCert.parseCertByAttributes("DN",certpath, keyType);
        List<String> certdn = new ArrayList<String>();
        try {
            File file = new File(path); //Text文件
            BufferedReader br = new BufferedReader(new FileReader(file)); //构造一个BufferedReader类来读取文件
            String s = null;
            while ((s = br.readLine()) != null) { //使用readLine方法，一次读一行
                String[] str = s.split("[|]");
                if (str[3].indexOf("CN") != -1) {
                    //System.out.println(str[3]);
                    if (Arrays.asList(dn).contains(str[3])) {    // DN是否在指定证书数组中
                        certdn.add(str[1]);
                    }
                }
            }
            br.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return certdn.toArray(new String[certdn.size()]);
    }

    /**
     * 获取加密工作密钥报文时，所需带密钥的报文数据
     *
     * @return
     */
    public static String[] getCUPSTCWorkingKey() {
        // 创建DocumentBuilderFactory对象
        DocumentBuilderFactory a = DocumentBuilderFactory.newInstance();
        List<String> NSSkeylablelist = new ArrayList<String>();
        try {
            // 创建DocumentBuilder对象
            DocumentBuilder b = a.newDocumentBuilder();
            // 通过DocumentBuilder对象的parse方法返回一个Document对象
            Document document = b.parse(ParameterUtil.localsymmpath);
            // 通过Document对象的getElementsByTagName()返根节点的一个list集合
            NodeList booklist = document.getElementsByTagName("SymmKey");
            for (int i = 0; i < booklist.getLength(); i++) {

                // 循环遍历获取每一个book
                Node book = booklist.item(i);
                // 通过Node对象的getAttributes()方法获取全的属性值
                NamedNodeMap bookmap = book.getAttributes();
                // 循环遍每一个book的属性值
                for (int j = 0; j < bookmap.getLength(); j++) {
                    @SuppressWarnings("unused")
                    Node node = bookmap.item(j);
                    // 通过Node对象的getNodeName()和getNodeValue()方法获取属性名和属性值
                }
                // 解析book节点的子节点
                NodeList childlist = book.getChildNodes();
                for (int t = 0; t < childlist.getLength(); t++) {
                    // 区分出text类型的node以及element类型的node
                    if (childlist.item(t).getNodeType() == Node.ELEMENT_NODE) {
                        if (childlist.item(t).getNodeName() == "KeyData") {
                            String Lists = childlist.item(t).getTextContent();
                            NSSkeylablelist.add(Lists);
                        }

                    }
                }
            }
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
        } catch (SAXException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return NSSkeylablelist.toArray(new String[NSSkeylablelist.size()]);
    }

    /**
     * 根据节点名称,获取xml文件节点属性值
     *
     * @param parameterUtilPath
     * @param elementName
     * @return
     */
    public static String[] getEleValFroXML(String parameterUtilPath, String elementName) {
		SAXReader reader = new SAXReader();
		List<String> list = new ArrayList<>();
		if (parameterUtilPath != null && !parameterUtilPath.isEmpty() && elementName != null && !elementName.isEmpty()) {
			try {
				org.dom4j.Document d = reader.read(parameterUtilPath);
				Element root = d.getRootElement();
				List<Element> elements = root.elements();
				String elementValue = null;

				for (Element element : elements) {
					elementValue = element.elementText(elementName);
					if (elementValue != null && !elementValue.isEmpty()) {
						list.add(elementValue);
					}
				}
			} catch (DocumentException e) {
				e.printStackTrace();
			}
		}
		return list.toArray(new String[list.size()]);
	}

    public static void main(String[] args) {
		String[] desEdes = getBankCode(ParameterUtil.localdetailpath,ParameterUtil.normalpath,"sm2");
		for (int i = 0; i <desEdes.length ; i++) {
			System.out.println(desEdes[i]);
		}
	}

}
