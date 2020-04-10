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
 * ���ļ����в���
 * <p>Title: ParseFile</p>
 * <p>Description: </p>
 *
 * @author maxf
 * @date 2019��8��13��
 */
public class ParseFile {

    /**
     * ��ȡkey��Ӧ��valueֵ
     *
     * @param key      ��ֵ
     * @param confpath �����ļ�·����Ϊnull��ʹ��Ĭ��·��
     * @return keyValue valueֵ
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
     * ��ȡ���ļ�����
     *
     * @return byte[]
     */
    public static byte[] getFileData(String filepath) {
        byte[] bfiledata = null;

        try {
            // ��ȡ���ļ�����
            File dir = new File(filepath);
            File[] f = dir.listFiles();

            if (null == f || f.length == 0) {
                Assert.fail(filepath + "Ŀ¼Ϊ��,�޷���ȡ�ļ�");
            } else if (f.length > 1) {
                Assert.fail("Ŀǰ��֧�ֶ�����ļ�ǩ��");
            } else {
                FileInputStream fis = new FileInputStream(f[0]);
                bfiledata = new byte[fis.available()];
                fis.read(bfiledata);
                fis.close();
            }
        } catch (Exception e) {
            Assert.fail("���ļ�ʧ�ܣ���" + e.getMessage());
        }
        return bfiledata;
    }

    /**
     * ��ȡ��������
     *
     * @param path
     * @return String[]
     */
    public static String[] parseBankCode(String path) {
        List<String> bankcode = new ArrayList<String>();
        try {
            File file = new File(path); //Text�ļ�
            BufferedReader br = new BufferedReader(new FileReader(file));    //����һ��BufferedReader������ȡ�ļ�
            String s = null;
            while ((s = br.readLine()) != null) {    //ʹ��readLine������һ�ζ�һ��
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
     * ��ȡ��������
     *
     * @param path     detail.conf�ļ�·��
     * @param certpath ֤��·��
     * @param keyType  ֤������
     * @return
     */
    public static String[] getBankCode(String path, String certpath, String keyType) {
        String[] dn = ParseCert.parseCertByAttributes("DN",certpath, keyType);
        List<String> certdn = new ArrayList<String>();
        try {
            File file = new File(path); //Text�ļ�
            BufferedReader br = new BufferedReader(new FileReader(file)); //����һ��BufferedReader������ȡ�ļ�
            String s = null;
            while ((s = br.readLine()) != null) { //ʹ��readLine������һ�ζ�һ��
                String[] str = s.split("[|]");
                if (str[3].indexOf("CN") != -1) {
                    //System.out.println(str[3]);
                    if (Arrays.asList(dn).contains(str[3])) {    // DN�Ƿ���ָ��֤��������
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
     * ��ȡ���ܹ�����Կ����ʱ���������Կ�ı�������
     *
     * @return
     */
    public static String[] getCUPSTCWorkingKey() {
        // ����DocumentBuilderFactory����
        DocumentBuilderFactory a = DocumentBuilderFactory.newInstance();
        List<String> NSSkeylablelist = new ArrayList<String>();
        try {
            // ����DocumentBuilder����
            DocumentBuilder b = a.newDocumentBuilder();
            // ͨ��DocumentBuilder�����parse��������һ��Document����
            Document document = b.parse(ParameterUtil.localsymmpath);
            // ͨ��Document�����getElementsByTagName()�����ڵ��һ��list����
            NodeList booklist = document.getElementsByTagName("SymmKey");
            for (int i = 0; i < booklist.getLength(); i++) {

                // ѭ��������ȡÿһ��book
                Node book = booklist.item(i);
                // ͨ��Node�����getAttributes()������ȡȫ������ֵ
                NamedNodeMap bookmap = book.getAttributes();
                // ѭ����ÿһ��book������ֵ
                for (int j = 0; j < bookmap.getLength(); j++) {
                    @SuppressWarnings("unused")
                    Node node = bookmap.item(j);
                    // ͨ��Node�����getNodeName()��getNodeValue()������ȡ������������ֵ
                }
                // ����book�ڵ���ӽڵ�
                NodeList childlist = book.getChildNodes();
                for (int t = 0; t < childlist.getLength(); t++) {
                    // ���ֳ�text���͵�node�Լ�element���͵�node
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
     * ���ݽڵ�����,��ȡxml�ļ��ڵ�����ֵ
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
