package qa.infosec.testng.netsign.dataprovider;

import cn.com.infosec.jce.provider.InfosecProvider;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.testng.Assert;
import qa.infosec.testng.netsign.dataprovider.util.ParameterUtil;
import qa.infosec.testng.netsign.dataprovider.util.ParseCert;
import qa.infosec.testng.netsign.dataprovider.util.ParseFile;
import qa.infosec.testng.netsign.dataprovider.util.Utils;

import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 组合数据源
 * <p>
 * Title: DataProviderUtil
 * </p>
 * <p>
 * Description:
 * </p>
 *
 * @author maxf
 * @date 2019年8月13日
 */
public class DataProviderUtil {

    static {
        Security.addProvider(new InfosecProvider());
    }

    /**
     * RSA对应的摘要算法
     *
     * @return
     */
    public static String[] RSAHashArrays() {
        List<String> rsalist = new ArrayList<String>();
        rsalist.add("MD5");
        rsalist.add("SHA1");
        rsalist.add("SHA224");
        rsalist.add("SHA256");
        rsalist.add("SHA384");
        rsalist.add("SHA512");
        return rsalist.toArray(new String[rsalist.size()]);
    }

    /**
     * 国密对应的摘要算法
     *
     * @return
     */
    public static String[] SM3HashArrays() {
        List<String> sm3list = new ArrayList<String>();
        sm3list.add("SM3");
        sm3list.add("SHA1");
        sm3list.add("SHA256");
        return sm3list.toArray(new String[sm3list.size()]);
    }

    /**
     * 二三类加密普通交易报文数据
     *
     * @return
     */
    public static String[] JsonDataList() {
        List<String> EncryptDatalist = new ArrayList<String>();
        EncryptDatalist.add("  {\"issInsCode\":   \"GFYH0001\"," + "\"priAccNo\":     \"6222027845126124255\","
                + "\"customerNm\":   \"黄灿\"," + "\"certifId\":     \"340104198501020815\","
                + "\"phoneNo\":      \"13100000014\"," + "\"msgCode\":      \"587644\"," + "\"subAccTp\":     \"2\","
                + "\"sex\":  \"1\"," + "\"nationality\":  \"CN\"," + "\"occupation\":   \"0001\","
                + "\"address\":      \"北京\"," + "\"validStart\":   \"20101111\"," + "\"validUntil\":   \"20201111\","
                + "\"reqResvFld\":   \"0\"," + "\"orgQryId\":     \"0007290020180103162957801765\"" + "}");
        EncryptDatalist.add("{ \"keyTp\":\"3\"," + "\"newKey\":\"7f3d752fec836b861ff7e0abc470b34a\"" + "}");
        EncryptDatalist.add(" { \"keyTp\":\"3\"," + "\"newKey\":\"7f3d752fec836b861ff7e0abc470b34a\""
                + "\"keyLabel\":\"55555\"" + "}");
        return EncryptDatalist.toArray(new String[EncryptDatalist.size()]);
    }

    /**
     * 银联二三类，加密并签名时，使用JSON字符串
     *
     * @return
     */
    public static String[] jsonEncryAndSignData() {
        List<String> EncryptDatalist = new ArrayList<String>();
        EncryptDatalist.add("{	\"cerVer\":       \"01\"," + "\"queryId\":      \"0007290020180104104733778626\","
                + "\"sendInsCode\":  \"SASS0001\"," + "\"txnType\":      \"SA008\"," + "\"version\":      \"1.0\","
                + "\"encryptData\":  {\"issInsCode\":   \"GFYH0001\"," + "\"priAccNo\":     \"6222027845126124255\","
                + "\"customerNm\":   \"黄灿\"," + "\"certifId\":     \"340104198501020815\","
                + "\"phoneNo\":      \"13100000014\"," + "\"msgCode\":      \"587644\"," + "\"subAccTp\":     \"2\","
                + "\"sex\":  \"1\"," + "\"nationality\":  \"CN\"," + "\"occupation\":   \"0001\","
                + "\"address\":      \"北京\"," + "\"validStart\":   \"20101111\"," + "\"validUntil\":   \"20201111\","
                + "\"reqResvFld\":   \"0\"," + "\"orgQryId\":     \"0007290020180103162957801765\"" + "}}");
        EncryptDatalist.add("{	\"cerVer\":\"01\"," + "\"queryId\":\"0007290020180104104733778626\","
                + "\"sendInsCode\":\"SASS0001\"," + "\"txnType\":\"SA002\"," + "\"version\":\"1.0\","
                + "\"encryptData\":  { \"keyTp\":\"3\"," + "\"newKey\":\"7f3d752fec836b861ff7e0abc470b34a\"" + "}}");
        EncryptDatalist.add("{	\"cerVer\":\"01\"," + "\"queryId\":\"0007290020180104104733778626\","
                + "\"sendInsCode\":\"SASS0001\"," + "\"txnType\":\"SA002\"," + "\"version\":\"1.0\","
                + "\"encryptData\":  { \"keyTp\":\"3\"," + "\"newKey\":\"7f3d752fec836b861ff7e0abc470b34a\""
                + "\"keyLabel\":\"55555\"" + "}}");
        return EncryptDatalist.toArray(new String[EncryptDatalist.size()]);
    }

    /**
     * 获取RSA、SM2证书DN，及其对应的摘要算法
     *
     * @param strpath
     * @return [alg, dn]
     */
    public static Object[][] resolveAlgDN(String strpath) {
        // 解析RSA证书，组合RSA数据源
        String[] rsaalg = RSAHashArrays();
        String[] signdn = ParseCert.parseCertByAttributes("DN", strpath, "RSA");
        int size1 = rsaalg.length * signdn.length;
        Object[][] algdn_rsa = new Object[size1][];
        for (int i = 0; i < rsaalg.length; i++) {
            for (int j = 0; j < signdn.length; j++) {
                algdn_rsa[--size1] = new Object[]{rsaalg[i], signdn[j]};
            }
        }

        // 解析国密证书，组合SM2数据源
        String[] sm3alg = SM3HashArrays();
        String[] sm2dn = ParseCert.parseCertByAttributes("DN", strpath, "sm2");
        int size2 = sm3alg.length * sm2dn.length;
        Object[][] algdn_sm2 = new Object[size2][];
        for (int i = 0; i < sm3alg.length; i++) {
            for (int j = 0; j < sm2dn.length; j++) {
                algdn_sm2[--size2] = new Object[]{sm3alg[i], sm2dn[j]};
            }
        }

        // 合并RSA和SM2
        int algdnsize = algdn_rsa.length + algdn_sm2.length;
        Object[][] algdn = new Object[algdnsize][];
        if (algdn_rsa.length == 0) {
            return algdn_sm2;
        } else if (algdn_sm2.length == 0) {
            return algdn_rsa;
        } else if (algdn_rsa.length != 0 && algdn_sm2.length != 0) {
            System.arraycopy(algdn_rsa, 0, algdn, 0, algdn_rsa.length);
            System.arraycopy(algdn_sm2, 0, algdn, algdn_rsa.length, algdn_sm2.length);

            return algdn;
        } else {
            System.out.println("no dataprovider");
            return null;
        }
    }

    /**
     * 获取机构代码及摘要
     *
     * @param certpath
     * @return 【alg, bankcode】
     */
    public static Object[][] bankCodeAlg(String certpath) {
        // 解析RSA证书对应的机构代码
        String[] bankcode_rsa = ParseFile.getBankCode(ParameterUtil.localdetailpath, certpath, "RSA");
        String[] alg_rsa = RSAHashArrays();
        int size_rsa = bankcode_rsa.length * alg_rsa.length;
        Object[][] tmp_rsa = new Object[size_rsa][];
        for (int i = 0; i < alg_rsa.length; i++) {
            for (int j = 0; j < bankcode_rsa.length; j++) {
                tmp_rsa[--size_rsa] = new Object[]{alg_rsa[i], bankcode_rsa[j]};
            }
        }

        // 解析SM2证书对应的机构代码
        String[] bankcode_sm2 = ParseFile.getBankCode(ParameterUtil.localdetailpath, certpath, "SM2");
        String[] alg_sm2 = SM3HashArrays();
        int size_sm2 = bankcode_sm2.length * alg_sm2.length;
        Object[][] tmp_sm2 = new Object[size_sm2][];
        for (int i = 0; i < alg_sm2.length; i++) {
            for (int j = 0; j < bankcode_sm2.length; j++) {
                tmp_sm2[--size_sm2] = new Object[]{alg_sm2[i], bankcode_sm2[j]};
            }
        }

        // 合并RSA和SM2
        int size = tmp_rsa.length + tmp_sm2.length;
        Object[][] tmp = new Object[size][];
        if (tmp_rsa.length == 0) {
            return tmp_sm2;
        } else if (tmp_sm2.length == 0) {
            return tmp_rsa;
        } else if (tmp_rsa.length != 0 && tmp_sm2.length != 0) {
            System.arraycopy(tmp_rsa, 0, tmp, 0, tmp_rsa.length);
            System.arraycopy(tmp_sm2, 0, tmp, tmp_rsa.length, tmp_sm2.length);

            return tmp;
        } else {
            System.out.println("no dataprovider");
            return null;
        }
    }

    /*
     * 加密证书不存在证书类型问题 根据签名证书类型，进行区分 返回参数顺序【encdn,keyText】
     */
    public static Object[][] keyTextWithDN(String certpath) {

        String[] certID = ParseCert.parseCertByAttributes("DN", certpath, null);
        String[] keyText = ParseFile.getCUPSTCWorkingKey();

        int size = certID.length * keyText.length;
        Object[][] tmp = new Object[size][];

        for (int i = 0; i < certID.length; i++) {
            for (int j = 0; j < keyText.length; j++) {
                tmp[--size] = new Object[]{certID[i], keyText[j]};
            }
        }
        return tmp;
    }

    /**
     * 获取JSON字符串数据及签名加密DN 由于加密证书无类型限制，故与签名证书DN使用同一张
     *
     * @param certpath
     * @return 【json,signdn,encdn】
     */
    public static Object[][] jsonSignDNAndEncryDN(String certpath) {
        String[] jsonData = jsonEncryAndSignData();
        String[] dn = ParseCert.parseCertByAttributes("DN", certpath, null);
        int size = jsonData.length * dn.length;
        Object[][] tmp = new Object[size][];
        for (int i = 0; i < jsonData.length; i++) {
            for (int j = 0; j < dn.length; j++) {
                tmp[--size] = new Object[]{jsonData[i], dn[j], dn[j]};
            }
        }
        return tmp;
    }

    /**
     * 获取JSON字符串数据及签名加密机构代码 由于加密证书无类型限制，故与签名行号使用同一张
     *
     * @param certpath
     * @return 【json,signbank,encbank】
     */
    public static Object[][] jsonSignAndEncryBank(String certpath) {
        String[] jsonData = jsonEncryAndSignData();
        String[] bankcode = ParseFile.getBankCode(ParameterUtil.localdetailpath, certpath, null);
        int size = jsonData.length * bankcode.length;
        Object[][] tmp = new Object[size][];
        for (int i = 0; i < jsonData.length; i++) {
            for (int j = 0; j < bankcode.length; j++) {
                tmp[--size] = new Object[]{jsonData[i], bankcode[j], bankcode[j]};
            }
        }
        return tmp;
    }

    /**
     * 获取密钥列表中RSA证书主题
     *
     * @return【dn】
     */
    public static String[] getRSAKeystoreDN() {
        SAXReader reader = new SAXReader();
        List<String> list = new ArrayList<>();

        try {
            Document d = reader.read(ParameterUtil.keystorepath);
            Element root = d.getRootElement();
            List<Element> elements = root.elements();
            String keysize = null;
            String subject = null;

            for (Element element : elements) {
                keysize = element.elementText("keysize");
                subject = element.elementText("subject");
                if (keysize != null && Integer.parseInt(keysize) != 256) {
                    if (subject != null && !subject.isEmpty()
                            && !subject.equals("C=cn,O=INFOSEC Technologies " + "RSA2048SUB,CN=shanxia")) {
                        list.add(subject);
                    }
                }
            }
        } catch (DocumentException e) {
            e.printStackTrace();
        }
        return list.toArray(new String[list.size()]);
    }

    /**
     * 获取密钥列表中国密证书主题
     *
     * @return【dn】
     */
    public static String[] getSM2KeystoreDN() {
        SAXReader reader = new SAXReader();
        List<String> list = new ArrayList<>();

        try {
            Document d = reader.read(ParameterUtil.keystorepath);
            Element root = d.getRootElement();
            List<Element> elements = root.elements();
            String keysize = null;
            String subject = null;

            for (Element element : elements) {
                keysize = element.elementText("keysize");
                subject = element.elementText("subject");

                if (keysize != null && Integer.parseInt(keysize) == 256) {
                    if (subject != null && !subject.isEmpty()) {
                        list.add(subject);
                    }
                }
            }
        } catch (DocumentException e) {
            e.printStackTrace();
        }
        return list.toArray(new String[list.size()]);
    }

    /*
     * 解析RSA证书，返回参数【cert】
     */
    public static Object[] getRsaCert(String strpath) {
        ArrayList<X509Certificate> cert = ParseCert.getCert(strpath, "RSA");
        return cert.toArray(new Object[cert.size()]);
    }

    /*
     * 解析SM2证书，返回参数【cert】
     */
    public static Object[] getSM2Cert(String strpath) {
        ArrayList<X509Certificate> cert = ParseCert.getCert(strpath, "SM2");
        return cert.toArray(new Object[cert.size()]);
    }

    /*
     * 合并RSA，SM2证书，返回参数【X509Certificate cert】
     */
    public static Object[] getCert(String strpath) {

        ArrayList<X509Certificate> rsaCert = ParseCert.getCert(strpath, "RSA");
        ArrayList<X509Certificate> sm2Cert = ParseCert.getCert(strpath, "SM2");
        int size = rsaCert.size() + sm2Cert.size();
        ArrayList<X509Certificate> cert = new ArrayList<>();

        if (rsaCert.size() == 0) {
            return sm2Cert.toArray(new Object[sm2Cert.size()]);
        } else if (sm2Cert.size() == 0) {
            return rsaCert.toArray(new Object[rsaCert.size()]);
        } else if (rsaCert.size() != 0 && sm2Cert.size() != 0) {
            for (int i = 0; i < sm2Cert.size(); i++) {
                cert.add(sm2Cert.get(i));
            }
            for (int i = 0; i < rsaCert.size(); i++) {
                cert.add(rsaCert.get(i));
            }
            return cert.toArray(new Object[size]);
        } else {
            System.out.println("no dataprovider");
            return null;
        }
    }

    /**
     * 根据证书路径、类型解析获取证书 keyTpye = sm2 获取国密证书 keyTpye = rsa 获取RSA证书 keyTpye = all
     * 获取所有类型证书
     *
     * @param strpath 证书存放路径
     * @param keyType 证书类型
     * @return【X509Certificate cert】
     */
    public static Object[] getCert(String strpath, String keyType) {
        ArrayList<X509Certificate> cert = ParseCert.getCert(strpath, keyType);

        return cert.toArray(new Object[cert.size()]);
    }

    /*
     * 获取密钥列表中所有证书的dn
     */
    public static String[] getKeystoreDN() {
        SAXReader reader = new SAXReader();
        List<String> list = new ArrayList<>();

        try {
            Document d = reader.read(ParameterUtil.keystorepath);
            Element root = d.getRootElement();
            List<Element> elements = root.elements();
            String subject = null;

            for (Element element : elements) {
                subject = element.elementText("subject");
                if (subject != null && !subject.isEmpty()) {
                    list.add(subject);
                }
            }
        } catch (DocumentException e) {
            e.printStackTrace();
        }
        return list.toArray(new String[list.size()]);
    }

    /*
     * 获取所有摘要算法
     */
    public static Object[] getAlg() {
        String[] rsaAlg = RSAHashArrays();
        String[] sm3Alg = SM3HashArrays();
        int rsaSize = rsaAlg.length;
        int sm3Size = sm3Alg.length;
        List<String> list = new ArrayList<>();
        // rsa摘要算法扩容
        rsaAlg = Arrays.copyOf(rsaAlg, rsaSize + sm3Size);
        // 复制sm3摘要算法数组内容到rsa摘要算法数组
        System.arraycopy(sm3Alg, 0, rsaAlg, rsaSize, sm3Size);
        for (int i = 0; i < rsaAlg.length; i++) {
            if (!list.contains(rsaAlg[i])) {
                list.add(rsaAlg[i]);
            }
        }
        return list.toArray(new String[list.size()]);
    }
//===========================================facePayment1.3新增======================================================

    /**
     * 参数为null或""
     *
     * @return
     */
    public static String[] Emptys() {
        List<String> emptylist = new ArrayList<String>();
        emptylist.add("");
        emptylist.add(null);
        return emptylist.toArray(new String[emptylist.size()]);
    }

    /**
     * 获取所有对称算法
     *
     * @return
     */
    public static Object[] getSymmetricalAlg(int ivLength) {
        List<String> list = new ArrayList<>();
        if (ivLength == 0) {
            list.add("SM4");
            list.add("AES");
            list.add("DES");
            list.add("DESEde");
            list.add("RC2");
            list.add("RC4");
        } else if (ivLength == 8) {
            list.add("DES");
            list.add("DESEde");
            list.add("RC2");
            list.add("RC4");
        } else if (ivLength == 16) {
            list.add("SM4");
            list.add("AES");
        }

        return list.toArray(new String[list.size()]);
    }

    /**
     * 获取对称密钥及密钥类型 ivEmpty = true 不反回含有/ECB的填充模式及RC4/RC2对称密钥算法
     *
     * @return
     */
    public static Object[] getSymmKeyAndAlg(int ivLength, boolean ivEmpty) {
        String key_length_8 = Utils.getRandomString(8);
        String key_length_16 = Utils.getRandomString(16);
        String key_length_24 = Utils.getRandomString(24);
        String key_length_32 = Utils.getRandomString(32);
        List<String> list = new ArrayList<>();
        if (ivEmpty) {
            if (ivLength == 0) {
                list.add("AES," + key_length_16);
                list.add("AES," + key_length_24);
                list.add("AES," + key_length_32);
                list.add("SM4," + key_length_16);
                list.add("3DES," + key_length_16);
                list.add("3DES," + key_length_24);
                list.add("DES," + key_length_8);
            } else if (ivLength == 8) {
                list.add("3DES," + key_length_16);
                list.add("3DES," + key_length_24);
                list.add("DES," + key_length_8);
            } else if (ivLength == 16) {
                list.add("AES," + key_length_16);
                list.add("AES," + key_length_24);
                list.add("AES," + key_length_32);
                list.add("SM4," + key_length_16);
            } else {
                Assert.fail("===请正确输入IV长度===");
                return null;
            }
        } else {
            if (ivLength == 0) {
                list.add("AES," + key_length_16);
                list.add("AES," + key_length_24);
                list.add("AES," + key_length_32);
                list.add("SM4," + key_length_16);
                list.add("3DES," + key_length_16);
                list.add("3DES," + key_length_24);
                list.add("DES," + key_length_8);
                list.add("RC4," + key_length_16);
                list.add("RC2," + key_length_8);
            } else if (ivLength == 8) {
                list.add("3DES," + key_length_16);
                list.add("3DES," + key_length_24);
                list.add("DES," + key_length_8);
                list.add("RC4," + key_length_16);
                list.add("RC2," + key_length_8);
            } else if (ivLength == 16) {
                list.add("AES," + key_length_16);
                list.add("AES," + key_length_24);
                list.add("AES," + key_length_32);
                list.add("SM4," + key_length_16);
            } else {
                Assert.fail("===请正确输入IV长度===");
                return null;
            }
        }
        return list.toArray(new String[list.size()]);
    }

    /**
     * 获取对称密钥算法填充模式
     *
     * @return
     */
    public static Object[] getModePadding(boolean ivEmpty) {
        List<String> listMode = new ArrayList<>();
        List<String> listPadding = new ArrayList<>();
        List<String> listModePadding = new ArrayList<>();
        if (ivEmpty) {
            listMode.add("/CBC");
            listMode.add("/CFB");
            listMode.add("/OFB");
        } else {
            listMode.add("/CBC");
            listMode.add("/CFB");
            listMode.add("/OFB");
            listMode.add("/ECB");
        }
        listPadding.add("/NoPadding");
        listPadding.add("/PKCS5Padding");
        listPadding.add("/PKCS7Padding");

        for (int i = 0; i < listMode.size(); i++) {
            for (int j = 0; j < listPadding.size(); j++) {
                listModePadding.add(listMode.get(i) + listPadding.get(j));
            }
        }
        return listModePadding.toArray(new String[listModePadding.size()]);
    }

    /**
     * 根据iv长度组合对称密钥及填充模式
     *
     * @param ivLength iv长度
     * @param ivEmpty  iv是否为空 当ivEmpty = true 不返回含有/ECB的填充模式
     * @return
     */
    public static Object[][] symmKeyAndModePadding(int ivLength, boolean ivEmpty) {
        Object[] symmKeyAndAlg = getSymmKeyAndAlg(ivLength, ivEmpty);
        Object[] modePadding = getModePadding(ivEmpty);
        int size = symmKeyAndAlg.length * modePadding.length;
        Object[][] tmp_all = new Object[size][];

        for (int i = 0; i < symmKeyAndAlg.length; i++) {
            for (int j = 0; j < modePadding.length; j++) {
                tmp_all[--size] = new Object[]{symmKeyAndAlg[i], modePadding[j]};
            }
        }
        return tmp_all;
    }

    /**
     * 解析对称密钥列表获取:keyLable、keyType、keyData
     *
     * @return
     */
    public static Object[] getKeyLbAndTpAndData(int ivLength) {
        String[] keyLables = ParseFile.getEleValFroXML(ParameterUtil.localsymmpath, "KeyLabel");
        String[] keyTypes = ParseFile.getEleValFroXML(ParameterUtil.localsymmpath, "KeyType");
        String[] keyData = ParseFile.getEleValFroXML(ParameterUtil.localsymmpath, "KeyData");
        List<String> list = new ArrayList<>();
        if (keyLables.length != 0 && keyTypes.length != 0 && keyData.length != 0) {
            for (int i = 0; i < keyLables.length; i++) {
                if (ivLength == 0) {
                    list.add(keyLables[i].trim() + "&" + keyTypes[i].trim() + "&" + keyData[i].trim());
                } else if (ivLength == 8) {
                    if ("DESEde".equals(keyTypes[i].trim()) || "DES".equals(keyTypes[i].trim())) {
                        list.add(keyLables[i].trim() + "&" + keyTypes[i].trim() + "&" + keyData[i].trim());
                    }
                } else if (ivLength == 16) {
                    if ("SM4".equals(keyTypes[i].trim()) || "AES".equals(keyTypes[i].trim())) {
                        list.add(keyLables[i].trim() + "&" + keyTypes[i].trim() + "&" + keyData[i].trim());
                    }
                } else {
                    Assert.fail("请正确输入iv长度");
                }
            }
        } else if (keyLables.length == 0) {
            Assert.fail("请检查KeyLable元素名称是否输入正确");
        } else if (keyTypes.length == 0) {
            Assert.fail("请检查KeyType元素名称是否输入正确");
        } else if (keyData.length == 0) {
            Assert.fail("请检查KeyData元素名称是否输入正确");
        }
        return list.toArray(new String[list.size()]);
    }

    /**
     * 根据iv长度组合对称密钥及填充模式,对称密钥信息包含keyData/keyLable/keyType
     *
     * @param ivLength iv长度
     * @param ivEmpty  iv是否为空 当ivEmpty = true 不反回含有/ECB的填充模式
     */
    public static Object[][] symmKeyWithModePadding(int ivLength, boolean ivEmpty) {
        Object[] symmKey = getKeyLbAndTpAndData(ivLength);
        Object[] modePadding = getModePadding(ivEmpty);
        int size = symmKey.length * modePadding.length;
        Object[][] tmp_all = new Object[size][];

        for (int i = 0; i < symmKey.length; i++) {
            for (int j = 0; j < modePadding.length; j++) {
                tmp_all[--size] = new Object[]{symmKey[i], modePadding[j]};
            }
        }
        return tmp_all;
    }

    /**
     * 根据iv长度组合对称密钥类型及填充模式
     *
     * @param ivLength iv长度
     * @param ivEmpty  iv是否为空 当ivEmpty = true 不反回含有/ECB的填充模式
     */
    public static Object[][] AlgWithModePadding(int ivLength, boolean ivEmpty) {
        Object[] symmetricalAlg = getSymmetricalAlg(ivLength);
        Object[] modePadding = getModePadding(ivEmpty);
        int size = symmetricalAlg.length * modePadding.length;
        Object[][] tmp_all = new Object[size][];

        for (int i = 0; i < symmetricalAlg.length; i++) {
            for (int j = 0; j < modePadding.length; j++) {
                tmp_all[--size] = new Object[]{symmetricalAlg[i], modePadding[j]};
            }
        }
        return tmp_all;
    }

    /**
     * 组合对称密钥及证书DN,对称密钥信息包含keyData/keyLable/keyType ivLength = 0 返回所有类型对称密钥 ivLength
     * = 8 返回类型为3DES/DES对称密钥 ivLength = 16 返回类型为AES/SM4对称密钥
     *
     * @param ivLength iv长度
     */
    public static Object[][] symmKeyWithDN(int ivLength) {
        Object[] symmKey = getKeyLbAndTpAndData(ivLength);
        Object[] dn = getKeystoreDN();
        int size = symmKey.length * dn.length;
        Object[][] tmp_all = new Object[size][];

        for (int i = 0; i < symmKey.length; i++) {
            for (int j = 0; j < dn.length; j++) {
                tmp_all[--size] = new Object[]{symmKey[i], dn[j]};
            }
        }
        return tmp_all;
    }

    /**
     * 非对称加密填充模式
     *
     * @return
     */
    public static Object[] asymmModeAndPadding() {
        List<String> list = new ArrayList<>();
        list.add("RSA");
        list.add("RSA/ECB/PKCS1Padding");
        return list.toArray(new String[list.size()]);
    }

    /**
     * 组合非对称加密填充模式及证书DN
     *
     * @return
     */
    public static Object[][] asymmModeAndPaddingWithDN() {
        Object[] modeAndPadding = asymmModeAndPadding();
        String[] keystoreDN = getKeystoreDN();
        int size = modeAndPadding.length * keystoreDN.length;
        Object[][] tmp = new Object[size][];
        for (int i = 0; i < modeAndPadding.length; i++) {
            for (int j = 0; j < keystoreDN.length; j++) {
                tmp[--size] = new Object[]{modeAndPadding[i], keystoreDN[j]};
            }
        }
        return tmp;
    }


    /**
     * 组合证书的Base64以及DN信息
     *
     * @param attr    证书信息，支持DN、SN、Bankcode
     * @param strpath 证书路径
     * @param keyType 证书类型
     * @return DN+Base64Cert
     */
    public static Object[] getBase64CertAndAttr(String attr, String strpath, String keyType) {
        Object[] obj = getCert(strpath, keyType);
        X509Certificate cert = null;
        String base64cert = null;
        String[] DNs = ParseCert.parseCertByAttributes(attr, strpath, keyType);
        List<String> list = new ArrayList<>();
        for (int i = 0; i < obj.length; i++) {
            cert = (X509Certificate) obj[i];
            base64cert = ParseCert.getBase64Cert(cert);
            list.add(DNs[i] + "%" + base64cert);
        }
        return list.toArray(new Object[list.size()]);
    }


    /**
     * 组合证书的Base64以及BankCode信息(证书的base64与BankCode实际未对应)
     *
     * @param strpath 证书路径
     * @param keyType 证书类型
     * @return SN+Base64Cert
     */
    public static Object[] getBase64CertAndBankCode(String strpath, String keyType) {
        Object[] obj = getCert(strpath, keyType);
        X509Certificate cert = null;
        String base64cert = null;
        String[] bankCodes = ParseFile.parseBankCode(ParameterUtil.localdetailpath);
        List<String> list = new ArrayList<>();
        for (int i = 0; i < obj.length; i++) {
            cert = (X509Certificate) obj[i];
            base64cert = ParseCert.getBase64Cert(cert);
            list.add(bankCodes[i] + "%" + base64cert);
        }
        return list.toArray(new Object[list.size()]);
    }

    /**
     * 根据证书路径、类型组合证书信息，Base64信息，对称加密算法
     *
     * @param strpath 证书路径
     * @param keyType 证书类型all返回所有证书，sm2返回国密证书，rsa返回RSA证书
     * @param length  length=0返回所有对称加密算法， length=8返回des/3des/rc2/rc4对称加密算法，
     *                length=16返回aes/sm4对称加密算法
     */
    public static Object[][] getAlgWithBase64CertAndAttr(String attr, String strpath, String keyType, int length) {
        Object[] base64CertAndDN = getBase64CertAndAttr(attr, strpath, keyType);
        Object[] symmetricalAlg = getSymmetricalAlg(length);
        int size = base64CertAndDN.length * symmetricalAlg.length;
        Object[][] obj = new Object[size][];

        for (int i = 0; i < symmetricalAlg.length; i++) {
            for (int j = 0; j < base64CertAndDN.length; j++) {
                obj[--size] = new Object[]{symmetricalAlg[i], base64CertAndDN[j]};
            }
        }
        return obj;
    }


    public static String[] getHashByType(String type) {
        String[] strings = null;
        if (type.toLowerCase().equals("rsa")) {
            strings = RSAHashArrays();
        } else if (type.toLowerCase().equals("sm2")) {
            strings = SM3HashArrays();
        } else if (type.toLowerCase().equals("all")) {
            strings = (String[]) getAlg();
        } else {
            Assert.fail("请正确输入摘要算法类型");
        }
        return strings;
    }

    /**
     * 获取RSA、SM2证书SN，及其对应的摘要算法
     *
     * @param strpath
     * @return [alg, sn]
     */
    public static Object[][] resolveAlgSN(String strpath) {
        // 解析RSA证书，组合RSA数据源
        String[] rsaalg = RSAHashArrays();
        String[] signdn = ParseCert.parseCertByAttributes("SN", strpath, "rsa");
        int size1 = rsaalg.length * signdn.length;
        Object[][] algdn_rsa = new Object[size1][];
        for (int i = 0; i < rsaalg.length; i++) {
            for (int j = 0; j < signdn.length; j++) {
                algdn_rsa[--size1] = new Object[]{rsaalg[i], signdn[j]};
            }
        }

        // 解析国密证书，组合SM2数据源
        String[] sm3alg = SM3HashArrays();
        String[] sm2dn = ParseCert.parseCertByAttributes("SN", strpath, "sm2");
        int size2 = sm3alg.length * sm2dn.length;
        Object[][] algdn_sm2 = new Object[size2][];
        for (int i = 0; i < sm3alg.length; i++) {
            for (int j = 0; j < sm2dn.length; j++) {
                algdn_sm2[--size2] = new Object[]{sm3alg[i], sm2dn[j]};
            }
        }

        // 合并RSA和SM2
        int algdnsize = algdn_rsa.length + algdn_sm2.length;
        Object[][] algdn = new Object[algdnsize][];
        if (algdn_rsa.length == 0) {
            return algdn_sm2;
        } else if (algdn_sm2.length == 0) {
            return algdn_rsa;
        } else if (algdn_rsa.length != 0 && algdn_sm2.length != 0) {
            System.arraycopy(algdn_rsa, 0, algdn, 0, algdn_rsa.length);
            System.arraycopy(algdn_sm2, 0, algdn, algdn_rsa.length, algdn_sm2.length);

            return algdn;
        } else {
            System.out.println("no dataprovider");
            return null;
        }
    }

    /**
     * 获取RSA、SM2证书DN、摘要算法及公钥证书
     *
     * @param strpath
     * @return [alg, dn , cert]
     * @throws IOException
     */
    public static Object[][] resolveAlgDNCert(String strpath) {
        // 解析RSA证书，组合RSA数据源
        String[] rsaalg = RSAHashArrays();
        String[] signdn = ParseCert.parseCertByAttributes("DN", strpath, "rsa");
        ArrayList<X509Certificate> rsacert = ParseCert.getCert(strpath, "RSA");
        String cert = null;
        List<String> certList = new ArrayList<String>();
        for (int i = 0; i < rsacert.size(); i++) {
            cert = ParseCert.getBase64Cert(rsacert.get(i));
            certList.add(cert);
        }
//        String[] cert = ParseCert.getBase64Cert(rsacert[]);
//        int size1 = rsaalg.length * signdn.length * certList.size();
        int size1 = rsaalg.length * signdn.length;
        Object[][] algdn_rsa = new Object[size1][];
        for (int i = 0; i < rsaalg.length; i++) {
            for (int j = 0; j < signdn.length; j++) {
                algdn_rsa[--size1] = new Object[]{rsaalg[i], signdn[j], certList.get(j)};
            }
        }

        // 解析国密证书，组合SM2数据源
        String[] sm3alg = SM3HashArrays();
        String[] sm2dn = ParseCert.parseCertByAttributes("DN", strpath, "sm2");
        ArrayList<X509Certificate> sm2cert = ParseCert.getCert(strpath, "SM2");
        String sm2cert2 = null;
        List<String> certList2 = new ArrayList<String>();
        for (int i = 0; i < sm2cert.size(); i++) {
            sm2cert2 = ParseCert.getBase64Cert(sm2cert.get(i));
            certList2.add(sm2cert2);
        }
//        int size2 = sm3alg.length * sm2dn.length * certList2.size();
        int size2 = sm3alg.length * sm2dn.length;
        Object[][] algdn_sm2 = new Object[size2][];
        for (int i = 0; i < sm3alg.length; i++) {
            for (int j = 0; j < sm2dn.length; j++) {
                algdn_sm2[--size2] = new Object[]{sm3alg[i], sm2dn[j], certList2.get(j)};
            }
        }

        // 合并RSA和SM2
        int algdnsize = algdn_rsa.length + algdn_sm2.length;
        Object[][] algdn = new Object[algdnsize][];
        if (algdn_rsa.length == 0) {
            return algdn_sm2;
        } else if (algdn_sm2.length == 0) {
            return algdn_rsa;
        } else if (algdn_rsa.length != 0 && algdn_sm2.length != 0) {
            System.arraycopy(algdn_rsa, 0, algdn, 0, algdn_rsa.length);
            System.arraycopy(algdn_sm2, 0, algdn, algdn_rsa.length, algdn_sm2.length);

            return algdn;
        } else {
            System.out.println("no dataprovider");
            return null;
        }
    }


    /**
     * 根据所需条件组合证书属性和摘要算法、对称算法
     *
     * @param attr     证书属性：支持返回DN、SN、BankCode
     * @param isDalg   是否组合摘要算法
     * @param isSalg   是否组合对称算法
     * @param certpath 证书路径
     * @param type     证书、摘要算法类型：RSA、SM2
     * @param length   对称算法组长度：length=0返回所有对称加密算法，
     *                 length=8返回des/3des/rc2/rc4对称加密算法，
     *                 length=16返回aes/sm4对称加密算法
     * @return
     */
    public static Object[][] composeCertAttrWithAlg(String attr, boolean isDalg, boolean isSalg,
                                                    String certpath, String type, int length) {
        String[] certStrs = null;
        String[] dAlgs = null;
        String[] sAlgs = null;
        // 组合证书属性及摘要算法对称算法
        if (attr != null && attr.length() != 0 && isDalg == true && isSalg == true) {
            certStrs = ParseCert.parseCertByAttributes(attr, certpath, type);
            dAlgs = getHashByType(type);
            sAlgs = (String[]) getSymmetricalAlg(length);
            int size = certStrs.length * dAlgs.length * sAlgs.length;
            Object[][] tmp = new Object[size][];

            for (int i = 0; i < sAlgs.length; i++) {
                for (int j = 0; j < dAlgs.length; j++) {
                    for (int k = 0; k < certStrs.length; k++) {
                        tmp[--size] = new Object[]{certStrs[k], dAlgs[j], sAlgs[i]};
                    }
                }
            }
            return tmp;
        }
        // 组合证书属性及摘要算法
        if (attr != null && attr.length() != 0 && isDalg == true && isSalg == false) {
            certStrs = ParseCert.parseCertByAttributes(attr, certpath, type);
            dAlgs = getHashByType(type);
            int size = certStrs.length * dAlgs.length;
            Object[][] tmp = new Object[size][];

            for (int j = 0; j < dAlgs.length; j++) {
                for (int k = 0; k < certStrs.length; k++) {
                    tmp[--size] = new Object[]{certStrs[k], dAlgs[j]};
                }
            }
            return tmp;
        }
        // 组合证书属性及对称算法
        if (attr != null && attr.length() != 0 && isDalg == false && isSalg == true) {
            certStrs = ParseCert.parseCertByAttributes(attr, certpath, type);
            sAlgs = (String[]) getSymmetricalAlg(length);
            int size = certStrs.length * sAlgs.length;
            Object[][] tmp = new Object[size][];

            for (int i = 0; i < sAlgs.length; i++) {
                for (int k = 0; k < certStrs.length; k++) {
                    tmp[--size] = new Object[]{certStrs[k], sAlgs[i]};
                }
            }
            return tmp;
        }
        // 仅返回证书属性
        if (attr != null && attr.length() != 0 && isDalg == false && isSalg == false) {
            certStrs = ParseCert.parseCertByAttributes(attr, certpath, type);
            int size = certStrs.length;
            Object[][] tmp = new Object[size][];

            for (int k = 0; k < certStrs.length; k++) {
                tmp[--size] = new Object[]{certStrs[k]};
            }
            return tmp;
        }
        // 仅返回摘要算法
        if (attr == null && isDalg == true && isSalg == false) {
            dAlgs = getHashByType(type);
            int size = dAlgs.length;
            Object[][] tmp = new Object[size][];

            for (int j = 0; j < dAlgs.length; j++) {
                tmp[--size] = new Object[]{dAlgs[j]};
            }
            return tmp;
        }

        // 仅返回对称算法
        if (attr == null && isDalg == false && isSalg == true) {
            sAlgs = (String[]) getSymmetricalAlg(length);
            int size = sAlgs.length;
            Object[][] tmp = new Object[size][];

            for (int i = 0; i < sAlgs.length; i++) {
                tmp[--size] = new Object[]{sAlgs[i]};
            }
            return tmp;
        }
        return null;
    }


    public static Object[][] getBase64CertAndAttrWithSAlg(String attr, String strpath, String keyType) {
        Object[] base64CertAndDN = getBase64CertAndAttr(attr, strpath, keyType);
        String[] hashByType = getHashByType(keyType);
        int size = base64CertAndDN.length * hashByType.length;
        Object[][] tmp = new Object[size][];
        for (int i = 0; i < hashByType.length; i++) {
            for (int j = 0; j < base64CertAndDN.length; j++) {
                tmp[--size] = new Object[]{base64CertAndDN[j], hashByType[i]};
                System.out.println(base64CertAndDN[j]);
                System.out.println(hashByType[i]);
            }
        }
        return tmp;
    }

    public static void main(String[] args) {
        Object[] alls = getCert(ParameterUtil.revokepath, "rsa");
        X509Certificate cert = null;
        for (int i = 0; i < alls.length ; i++) {
            cert = (X509Certificate) alls[i];
            System.out.println(cert.getSubjectDN().getName());
        }
    }
}
