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
 * @author zhaoyongzhi
 * @date 2020年04月13日
 */
public class DataProviderUtil {

    static {
        Security.addProvider(new InfosecProvider());
    }

    /**
     * RSA对应的摘要算法
     */
    public static String[] RSAHashArrays() {
        List<String> rsalist = new ArrayList<>();
        rsalist.add("MD5");
        rsalist.add("SHA1");
        rsalist.add("SHA224");
        rsalist.add("SHA256");
        rsalist.add("SHA384");
        rsalist.add("SHA512");
        return rsalist.toArray(new String[0]);
    }

    /**
     * 国密对应的摘要算法
     */
    public static String[] SM3HashArrays() {
        List<String> sm3list = new ArrayList<>();
        sm3list.add("SM3");
        sm3list.add("SHA1");
        sm3list.add("SHA256");
        return sm3list.toArray(new String[0]);
    }

    /**
     * 二三类加密普通交易报文数据
     */
    public static String[] JsonDataList() {
        List<String> EncryptDatalist = new ArrayList<>();
        EncryptDatalist.add("  {\"issInsCode\":   \"GFYH0001\"," + "\"priAccNo\":     \"6222027845126124255\","
                + "\"customerNm\":   \"黄灿\"," + "\"certifId\":     \"340104198501020815\","
                + "\"phoneNo\":      \"13100000014\"," + "\"msgCode\":      \"587644\"," + "\"subAccTp\":     \"2\","
                + "\"sex\":  \"1\"," + "\"nationality\":  \"CN\"," + "\"occupation\":   \"0001\","
                + "\"address\":      \"北京\"," + "\"validStart\":   \"20101111\"," + "\"validUntil\":   \"20201111\","
                + "\"reqResvFld\":   \"0\"," + "\"orgQryId\":     \"0007290020180103162957801765\"" + "}");
        EncryptDatalist.add("{ \"keyTp\":\"3\"," + "\"newKey\":\"7f3d752fec836b861ff7e0abc470b34a\"" + "}");
        EncryptDatalist.add(" { \"keyTp\":\"3\"," + "\"newKey\":\"7f3d752fec836b861ff7e0abc470b34a\""
                + "\"keyLabel\":\"55555\"" + "}");
        return EncryptDatalist.toArray(new String[0]);
    }

    /**
     * 银联二三类，加密并签名时，使用JSON字符串
     */
    public static String[] jsonEncryAndSignData() {
        List<String> EncryptDatalist = new ArrayList<>();
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
        return EncryptDatalist.toArray(new String[0]);
    }

    /**
     * 获取RSA、SM2证书DN，及其对应的摘要算法
     *
     * @param strpath 证书路径
     * @return [alg, dn]
     */
    public static Object[][] resolveAlgDN(String strpath) {
        // 解析RSA证书，组合RSA数据源
        String[] rsaalg = RSAHashArrays();
        String[] signdn = ParseCert.parseCertByAttributes("DN", strpath, "RSA");
        assert signdn != null;
        int size1 = rsaalg.length * signdn.length;
        Object[][] algdn_rsa = new Object[size1][];
        for (String value : rsaalg) {
            for (String s : signdn) {
                algdn_rsa[--size1] = new Object[]{value, s};
            }
        }

        // 解析国密证书，组合SM2数据源
        String[] sm3alg = SM3HashArrays();
        String[] sm2dn = ParseCert.parseCertByAttributes("DN", strpath, "sm2");
        assert sm2dn != null;
        int size2 = sm3alg.length * sm2dn.length;
        Object[][] algdn_sm2 = new Object[size2][];
        for (String value : sm3alg) {
            for (String s : sm2dn) {
                algdn_sm2[--size2] = new Object[]{value, s};
            }
        }

        // 合并RSA和SM2
        int algdnsize = algdn_rsa.length + algdn_sm2.length;
        Object[][] algdn = new Object[algdnsize][];
        if (algdn_rsa.length == 0) {
            return algdn_sm2;
        } else if (algdn_sm2.length == 0) {
            return algdn_rsa;
        } else {
            System.arraycopy(algdn_rsa, 0, algdn, 0, algdn_rsa.length);
            System.arraycopy(algdn_sm2, 0, algdn, algdn_rsa.length, algdn_sm2.length);
            return algdn;
        }
    }

    /**
     * 获取机构代码及摘要
     *
     * @param certpath 证书路径
     * @return 【alg, bankcode】
     */
    public static Object[][] bankCodeAlg(String certpath) {
        // 解析RSA证书对应的机构代码
        String[] bankcode_rsa = ParseFile.getBankCode(ParameterUtil.localdetailpath, certpath, "RSA");
        String[] alg_rsa = RSAHashArrays();
        int size_rsa = bankcode_rsa.length * alg_rsa.length;
        Object[][] tmp_rsa = new Object[size_rsa][];
        for (String s : alg_rsa) {
            for (String value : bankcode_rsa) {
                tmp_rsa[--size_rsa] = new Object[]{s, value};
            }
        }

        // 解析SM2证书对应的机构代码
        String[] bankcode_sm2 = ParseFile.getBankCode(ParameterUtil.localdetailpath, certpath, "SM2");
        String[] alg_sm2 = SM3HashArrays();
        int size_sm2 = bankcode_sm2.length * alg_sm2.length;
        Object[][] tmp_sm2 = new Object[size_sm2][];
        for (String s : alg_sm2) {
            for (String value : bankcode_sm2) {
                tmp_sm2[--size_sm2] = new Object[]{s, value};
            }
        }

        // 合并RSA和SM2
        int size = tmp_rsa.length + tmp_sm2.length;
        Object[][] tmp = new Object[size][];
        if (tmp_rsa.length == 0) {
            return tmp_sm2;
        } else if (tmp_sm2.length == 0) {
            return tmp_rsa;
        } else {
            System.arraycopy(tmp_rsa, 0, tmp, 0, tmp_rsa.length);
            System.arraycopy(tmp_sm2, 0, tmp, tmp_rsa.length, tmp_sm2.length);
            return tmp;
        }
    }

    /*
     * 加密证书不存在证书类型问题 根据签名证书类型，进行区分 返回参数顺序【encdn,keyText】
     */
    public static Object[][] keyTextWithDN(String certpath) {

        String[] certID = ParseCert.parseCertByAttributes("DN", certpath, null);
        String[] keyText = ParseFile.getCUPSTCWorkingKey();

        assert certID != null;
        int size = certID.length * keyText.length;
        Object[][] tmp = new Object[size][];

        for (String s : certID) {
            for (String value : keyText) {
                tmp[--size] = new Object[]{s, value};
            }
        }
        return tmp;
    }

    /**
     * 获取JSON字符串数据及签名加密DN 由于加密证书无类型限制，故与签名证书DN使用同一张
     *
     * @param certpath 证书路径
     * @return 【json,signdn,encdn】
     */
    public static Object[][] jsonSignDNAndEncryDN(String certpath) {
        String[] jsonData = jsonEncryAndSignData();
        String[] dn = ParseCert.parseCertByAttributes("DN", certpath, null);
        assert dn != null;
        int size = jsonData.length * dn.length;
        Object[][] tmp = new Object[size][];
        for (String jsonDatum : jsonData) {
            for (String s : dn) {
                tmp[--size] = new Object[]{jsonDatum, s, s};
            }
        }
        return tmp;
    }

    /**
     * 获取JSON字符串数据及签名加密机构代码 由于加密证书无类型限制，故与签名行号使用同一张
     *
     * @param certpath 证书路径
     * @return 【json,signbank,encbank】
     */
    public static Object[][] jsonSignAndEncryBank(String certpath) {
        String[] jsonData = jsonEncryAndSignData();
        String[] bankcode = ParseFile.getBankCode(ParameterUtil.localdetailpath, certpath, null);
        int size = jsonData.length * bankcode.length;
        Object[][] tmp = new Object[size][];
        for (String jsonDatum : jsonData) {
            for (String s : bankcode) {
                tmp[--size] = new Object[]{jsonDatum, s, s};
            }
        }
        return tmp;
    }

    /**
     * 获取密钥列表中RSA证书主题
     */
    public static String[] getRSAKeystoreDN() {
        SAXReader reader = new SAXReader();
        List<String> list = new ArrayList<>();

        try {
            Document d = reader.read(ParameterUtil.keystorepath);
            Element root = d.getRootElement();
            List<Element> elements = root.elements();
            String keysize;
            String subject;

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
        return list.toArray(new String[0]);
    }

    /**
     * 获取密钥列表中国密证书主题
     */
    public static String[] getSM2KeystoreDN() {
        SAXReader reader = new SAXReader();
        List<String> list = new ArrayList<>();

        try {
            Document d = reader.read(ParameterUtil.keystorepath);
            Element root = d.getRootElement();
            List<Element> elements = root.elements();
            String keysize;
            String subject;

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
        return list.toArray(new String[0]);
    }

    /*
     * 解析RSA证书，返回参数【cert】
     */
    public static Object[] getRsaCert(String strpath) {
        ArrayList<X509Certificate> cert = ParseCert.getCert(strpath, "RSA");
        return cert.toArray(new Object[0]);
    }

    /*
     * 解析SM2证书，返回参数【cert】
     */
    public static Object[] getSM2Cert(String strpath) {
        ArrayList<X509Certificate> cert = ParseCert.getCert(strpath, "SM2");
        return cert.toArray(new Object[0]);
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
            return sm2Cert.toArray(new Object[0]);
        } else if (sm2Cert.size() == 0) {
            return rsaCert.toArray(new Object[0]);
        } else {
            cert.addAll(sm2Cert);
            cert.addAll(rsaCert);
            return cert.toArray(new Object[size]);
        }
    }

    /**
     * 根据证书路径、类型解析获取证书 keyTpye = sm2 获取国密证书 keyTpye = rsa 获取RSA证书 keyTpye = all
     * 获取所有类型证书
     *
     * @param strpath 证书存放路径
     * @param keyType 证书类型
     */
    public static Object[] getCert(String strpath, String keyType) {
        ArrayList<X509Certificate> cert = ParseCert.getCert(strpath, keyType);

        return cert.toArray(new Object[0]);
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
            String subject;

            for (Element element : elements) {
                subject = element.elementText("subject");
                if (subject != null && !subject.isEmpty()) {
                    list.add(subject);
                }
            }
        } catch (DocumentException e) {
            e.printStackTrace();
        }
        return list.toArray(new String[0]);
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
        for (String s : rsaAlg) {
            if (!list.contains(s)) {
                list.add(s);
            }
        }
        return list.toArray(new String[0]);
    }
//===========================================facePayment1.3新增======================================================

    /**
     * 参数为null或""
     */
    public static String[] Emptys() {
        List<String> emptylist = new ArrayList<>();
        emptylist.add("");
        emptylist.add(null);
        return emptylist.toArray(new String[0]);
    }

    /**
     * 获取所有对称算法
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

        return list.toArray(new String[0]);
    }

    /**
     * 获取对称密钥及密钥类型 ivEmpty = true 不反回含有/ECB的填充模式及RC4/RC2对称密钥算法
     *
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
        return list.toArray(new String[0]);
    }

    /**
     * 获取对称密钥算法填充模式
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

        for (String value : listMode) {
            for (String s : listPadding) {
                listModePadding.add(value + s);
            }
        }
        return listModePadding.toArray(new String[0]);
    }

    /**
     * 根据iv长度组合对称密钥及填充模式
     *
     * @param ivLength iv长度
     * @param ivEmpty  iv是否为空 当ivEmpty = true 不返回含有/ECB的填充模式
     */
    public static Object[][] symmKeyAndModePadding(int ivLength, boolean ivEmpty) {
        Object[] symmKeyAndAlg = getSymmKeyAndAlg(ivLength, ivEmpty);
        Object[] modePadding = getModePadding(ivEmpty);
        assert symmKeyAndAlg != null;
        int size = symmKeyAndAlg.length * modePadding.length;
        Object[][] tmp_all = new Object[size][];

        for (Object value : symmKeyAndAlg) {
            for (Object o : modePadding) {
                tmp_all[--size] = new Object[]{value, o};
            }
        }
        return tmp_all;
    }

    /**
     * 解析对称密钥列表获取:keyLable、keyType、keyData
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
        } else {
            Assert.fail("请检查KeyData元素名称是否输入正确");
        }
        return list.toArray(new String[0]);
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

        for (Object value : symmKey) {
            for (Object o : modePadding) {
                tmp_all[--size] = new Object[]{value, o};
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

        for (Object value : symmetricalAlg) {
            for (Object o : modePadding) {
                tmp_all[--size] = new Object[]{value, o};
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

        for (Object value : symmKey) {
            for (Object o : dn) {
                tmp_all[--size] = new Object[]{value, o};
            }
        }
        return tmp_all;
    }

    /**
     * 非对称加密填充模式
     */
    public static Object[] asymmModeAndPadding() {
        List<String> list = new ArrayList<>();
        list.add("RSA");
        list.add("RSA/ECB/PKCS1Padding");
        return list.toArray(new String[0]);
    }

    /**
     * 组合非对称加密填充模式及证书DN
     */
    public static Object[][] asymmModeAndPaddingWithDN() {
        Object[] modeAndPadding = asymmModeAndPadding();
        String[] keystoreDN = getKeystoreDN();
        int size = modeAndPadding.length * keystoreDN.length;
        Object[][] tmp = new Object[size][];
        for (Object o : modeAndPadding) {
            for (String s : keystoreDN) {
                tmp[--size] = new Object[]{o, s};
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
        X509Certificate cert;
        String base64cert;
        String[] DNs = ParseCert.parseCertByAttributes(attr, strpath, keyType);
        List<String> list = new ArrayList<>();
        for (int i = 0; i < obj.length; i++) {
            cert = (X509Certificate) obj[i];
            base64cert = ParseCert.getBase64Cert(cert);
            assert DNs != null;
            list.add(DNs[i] + "%" + base64cert);
        }
        return list.toArray(new Object[0]);
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
        X509Certificate cert;
        String base64cert;
        String[] bankCodes = ParseFile.parseBankCode(ParameterUtil.localdetailpath);
        List<String> list = new ArrayList<>();
        for (int i = 0; i < obj.length; i++) {
            cert = (X509Certificate) obj[i];
            base64cert = ParseCert.getBase64Cert(cert);
            list.add(bankCodes[i] + "%" + base64cert);
        }
        return list.toArray(new Object[0]);
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

        for (Object value : symmetricalAlg) {
            for (Object o : base64CertAndDN) {
                obj[--size] = new Object[]{value, o};
            }
        }
        return obj;
    }


    public static String[] getHashByType(String type) {
        String[] strings = null;
        switch (type.toLowerCase()) {
            case "rsa":
                strings = RSAHashArrays();
                break;
            case "sm2":
                strings = SM3HashArrays();
                break;
            case "all":
                strings = (String[]) getAlg();
                break;
            default:
                Assert.fail("请正确输入摘要算法类型");
                break;
        }
        return strings;
    }

    /**
     * 获取RSA、SM2证书SN，及其对应的摘要算法
     *
     * @param strpath 证书路径
     * @return [alg, sn]
     */
    public static Object[][] resolveAlgSN(String strpath) {
        // 解析RSA证书，组合RSA数据源
        String[] rsaalg = RSAHashArrays();
        String[] signdn = ParseCert.parseCertByAttributes("SN", strpath, "rsa");
        assert signdn != null;
        int size1 = rsaalg.length * signdn.length;
        Object[][] algdn_rsa = new Object[size1][];
        for (String item : rsaalg) {
            for (String s : signdn) {
                algdn_rsa[--size1] = new Object[]{item, s};
            }
        }

        // 解析国密证书，组合SM2数据源
        String[] sm3alg = SM3HashArrays();
        String[] sm2dn = ParseCert.parseCertByAttributes("SN", strpath, "sm2");
        assert sm2dn != null;
        int size2 = sm3alg.length * sm2dn.length;
        Object[][] algdn_sm2 = new Object[size2][];
        for (String value : sm3alg) {
            for (String s : sm2dn) {
                algdn_sm2[--size2] = new Object[]{value, s};
            }
        }

        // 合并RSA和SM2
        int algdnsize = algdn_rsa.length + algdn_sm2.length;
        Object[][] algdn = new Object[algdnsize][];
        if (algdn_rsa.length == 0) {
            return algdn_sm2;
        } else if (algdn_sm2.length == 0) {
            return algdn_rsa;
        } else {
            System.arraycopy(algdn_rsa, 0, algdn, 0, algdn_rsa.length);
            System.arraycopy(algdn_sm2, 0, algdn, algdn_rsa.length, algdn_sm2.length);
            return algdn;
        }
    }

    /**
     * 获取RSA、SM2证书DN、摘要算法及公钥证书
     *
     * @param strpath 证书路径
     * @return [alg, dn , cert]
     */
    public static Object[][] resolveAlgDNCert(String strpath) {
        // 解析RSA证书，组合RSA数据源
        String[] rsaalg = RSAHashArrays();
        String[] signdn = ParseCert.parseCertByAttributes("DN", strpath, "rsa");
        ArrayList<X509Certificate> rsacert = ParseCert.getCert(strpath, "RSA");
        String cert;
        List<String> certList = new ArrayList<>();
        for (X509Certificate certificate : rsacert) {
            cert = ParseCert.getBase64Cert(certificate);
            certList.add(cert);
        }
        assert signdn != null;
        int size1 = rsaalg.length * signdn.length;
        Object[][] algdn_rsa = new Object[size1][];
        for (String value : rsaalg) {
            for (int j = 0; j < signdn.length; j++) {
                algdn_rsa[--size1] = new Object[]{value, signdn[j], certList.get(j)};
            }
        }

        // 解析国密证书，组合SM2数据源
        String[] sm3alg = SM3HashArrays();
        String[] sm2dn = ParseCert.parseCertByAttributes("DN", strpath, "sm2");
        ArrayList<X509Certificate> sm2cert = ParseCert.getCert(strpath, "SM2");
        String sm2cert2;
        List<String> certList2 = new ArrayList<>();
        for (X509Certificate x509Certificate : sm2cert) {
            sm2cert2 = ParseCert.getBase64Cert(x509Certificate);
            certList2.add(sm2cert2);
        }
        assert sm2dn != null;
        int size2 = sm3alg.length * sm2dn.length;
        Object[][] algdn_sm2 = new Object[size2][];
        for (String s : sm3alg) {
            for (int j = 0; j < sm2dn.length; j++) {
                algdn_sm2[--size2] = new Object[]{s, sm2dn[j], certList2.get(j)};
            }
        }

        // 合并RSA和SM2
        int algdnsize = algdn_rsa.length + algdn_sm2.length;
        Object[][] algdn = new Object[algdnsize][];
        if (algdn_rsa.length == 0) {
            return algdn_sm2;
        } else if (algdn_sm2.length == 0) {
            return algdn_rsa;
        } else {
            System.arraycopy(algdn_rsa, 0, algdn, 0, algdn_rsa.length);
            System.arraycopy(algdn_sm2, 0, algdn, algdn_rsa.length, algdn_sm2.length);
            return algdn;
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
     */
    public static Object[][] composeCertAttrWithAlg(String attr, boolean isDalg, boolean isSalg,
                                                    String certpath, String type, int length) {
        String[] certStrs;
        String[] dAlgs;
        String[] sAlgs;
        // 组合证书属性及摘要算法对称算法
        if (attr != null && attr.length() != 0 && isDalg && isSalg) {
            certStrs = ParseCert.parseCertByAttributes(attr, certpath, type);
            dAlgs = getHashByType(type);
            sAlgs = (String[]) getSymmetricalAlg(length);
            assert certStrs != null;
            int size = certStrs.length * dAlgs.length * sAlgs.length;
            Object[][] tmp = new Object[size][];

            for (String sAlg : sAlgs) {
                for (String dAlg : dAlgs) {
                    for (String certStr : certStrs) {
                        tmp[--size] = new Object[]{certStr, dAlg, sAlg};
                    }
                }
            }
            return tmp;
        }
        // 组合证书属性及摘要算法
        if (attr != null && attr.length() != 0 && isDalg) {
            certStrs = ParseCert.parseCertByAttributes(attr, certpath, type);
            dAlgs = getHashByType(type);
            assert certStrs != null;
            int size = certStrs.length * dAlgs.length;
            Object[][] tmp = new Object[size][];

            for (String dAlg : dAlgs) {
                for (String certStr : certStrs) {
                    tmp[--size] = new Object[]{certStr, dAlg};
                }
            }
            return tmp;
        }
        // 组合证书属性及对称算法
        if (attr != null && attr.length() != 0 && isSalg) {
            certStrs = ParseCert.parseCertByAttributes(attr, certpath, type);
            sAlgs = (String[]) getSymmetricalAlg(length);
            assert certStrs != null;
            int size = certStrs.length * sAlgs.length;
            Object[][] tmp = new Object[size][];

            for (String sAlg : sAlgs) {
                for (String certStr : certStrs) {
                    tmp[--size] = new Object[]{certStr, sAlg};
                }
            }
            return tmp;
        }
        // 仅返回证书属性
        if (attr != null && attr.length() != 0) {
            certStrs = ParseCert.parseCertByAttributes(attr, certpath, type);
            assert certStrs != null;
            int size = certStrs.length;
            Object[][] tmp = new Object[size][];

            for (String certStr : certStrs) {
                tmp[--size] = new Object[]{certStr};
                System.out.println(certStr);
            }
            return tmp;
        }
        // 仅返回摘要算法
        if (attr == null && isDalg) {
            dAlgs = getHashByType(type);
            int size = dAlgs.length;
            Object[][] tmp = new Object[size][];

            for (String dAlg : dAlgs) {
                tmp[--size] = new Object[]{dAlg};
            }
            return tmp;
        }

        // 仅返回对称算法
        if (attr == null && isSalg) {
            sAlgs = (String[]) getSymmetricalAlg(length);
            int size = sAlgs.length;
            Object[][] tmp = new Object[size][];

            for (String sAlg : sAlgs) {
                tmp[--size] = new Object[]{sAlg};
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
        for (String s : hashByType) {
            for (Object o : base64CertAndDN) {
                tmp[--size] = new Object[]{o, s};
            }
        }
        return tmp;
    }

    public static void main(String[] args) {
        String[] strings = RSAHashArrays();
        for (String s : strings) {
            System.out.println(s);
        }
    }
}
