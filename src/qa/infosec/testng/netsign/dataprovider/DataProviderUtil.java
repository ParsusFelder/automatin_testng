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
 * �������Դ
 * <p>
 * Title: DataProviderUtil
 * </p>
 * <p>
 * Description:
 * </p>
 *
 * @author zhaoyongzhi
 * @date 2020��04��13��
 */
public class DataProviderUtil {

    static {
        Security.addProvider(new InfosecProvider());
    }

    /**
     * RSA��Ӧ��ժҪ�㷨
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
     * ���ܶ�Ӧ��ժҪ�㷨
     */
    public static String[] SM3HashArrays() {
        List<String> sm3list = new ArrayList<>();
        sm3list.add("SM3");
        sm3list.add("SHA1");
        sm3list.add("SHA256");
        return sm3list.toArray(new String[0]);
    }

    /**
     * �����������ͨ���ױ�������
     */
    public static String[] JsonDataList() {
        List<String> EncryptDatalist = new ArrayList<>();
        EncryptDatalist.add("  {\"issInsCode\":   \"GFYH0001\"," + "\"priAccNo\":     \"6222027845126124255\","
                + "\"customerNm\":   \"�Ʋ�\"," + "\"certifId\":     \"340104198501020815\","
                + "\"phoneNo\":      \"13100000014\"," + "\"msgCode\":      \"587644\"," + "\"subAccTp\":     \"2\","
                + "\"sex\":  \"1\"," + "\"nationality\":  \"CN\"," + "\"occupation\":   \"0001\","
                + "\"address\":      \"����\"," + "\"validStart\":   \"20101111\"," + "\"validUntil\":   \"20201111\","
                + "\"reqResvFld\":   \"0\"," + "\"orgQryId\":     \"0007290020180103162957801765\"" + "}");
        EncryptDatalist.add("{ \"keyTp\":\"3\"," + "\"newKey\":\"7f3d752fec836b861ff7e0abc470b34a\"" + "}");
        EncryptDatalist.add(" { \"keyTp\":\"3\"," + "\"newKey\":\"7f3d752fec836b861ff7e0abc470b34a\""
                + "\"keyLabel\":\"55555\"" + "}");
        return EncryptDatalist.toArray(new String[0]);
    }

    /**
     * ���������࣬���ܲ�ǩ��ʱ��ʹ��JSON�ַ���
     */
    public static String[] jsonEncryAndSignData() {
        List<String> EncryptDatalist = new ArrayList<>();
        EncryptDatalist.add("{	\"cerVer\":       \"01\"," + "\"queryId\":      \"0007290020180104104733778626\","
                + "\"sendInsCode\":  \"SASS0001\"," + "\"txnType\":      \"SA008\"," + "\"version\":      \"1.0\","
                + "\"encryptData\":  {\"issInsCode\":   \"GFYH0001\"," + "\"priAccNo\":     \"6222027845126124255\","
                + "\"customerNm\":   \"�Ʋ�\"," + "\"certifId\":     \"340104198501020815\","
                + "\"phoneNo\":      \"13100000014\"," + "\"msgCode\":      \"587644\"," + "\"subAccTp\":     \"2\","
                + "\"sex\":  \"1\"," + "\"nationality\":  \"CN\"," + "\"occupation\":   \"0001\","
                + "\"address\":      \"����\"," + "\"validStart\":   \"20101111\"," + "\"validUntil\":   \"20201111\","
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
     * ��ȡRSA��SM2֤��DN�������Ӧ��ժҪ�㷨
     *
     * @param strpath ֤��·��
     * @return [alg, dn]
     */
    public static Object[][] resolveAlgDN(String strpath) {
        // ����RSA֤�飬���RSA����Դ
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

        // ��������֤�飬���SM2����Դ
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

        // �ϲ�RSA��SM2
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
     * ��ȡ�������뼰ժҪ
     *
     * @param certpath ֤��·��
     * @return ��alg, bankcode��
     */
    public static Object[][] bankCodeAlg(String certpath) {
        // ����RSA֤���Ӧ�Ļ�������
        String[] bankcode_rsa = ParseFile.getBankCode(ParameterUtil.localdetailpath, certpath, "RSA");
        String[] alg_rsa = RSAHashArrays();
        int size_rsa = bankcode_rsa.length * alg_rsa.length;
        Object[][] tmp_rsa = new Object[size_rsa][];
        for (String s : alg_rsa) {
            for (String value : bankcode_rsa) {
                tmp_rsa[--size_rsa] = new Object[]{s, value};
            }
        }

        // ����SM2֤���Ӧ�Ļ�������
        String[] bankcode_sm2 = ParseFile.getBankCode(ParameterUtil.localdetailpath, certpath, "SM2");
        String[] alg_sm2 = SM3HashArrays();
        int size_sm2 = bankcode_sm2.length * alg_sm2.length;
        Object[][] tmp_sm2 = new Object[size_sm2][];
        for (String s : alg_sm2) {
            for (String value : bankcode_sm2) {
                tmp_sm2[--size_sm2] = new Object[]{s, value};
            }
        }

        // �ϲ�RSA��SM2
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
     * ����֤�鲻����֤���������� ����ǩ��֤�����ͣ��������� ���ز���˳��encdn,keyText��
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
     * ��ȡJSON�ַ������ݼ�ǩ������DN ���ڼ���֤�����������ƣ�����ǩ��֤��DNʹ��ͬһ��
     *
     * @param certpath ֤��·��
     * @return ��json,signdn,encdn��
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
     * ��ȡJSON�ַ������ݼ�ǩ�����ܻ������� ���ڼ���֤�����������ƣ�����ǩ���к�ʹ��ͬһ��
     *
     * @param certpath ֤��·��
     * @return ��json,signbank,encbank��
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
     * ��ȡ��Կ�б���RSA֤������
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
     * ��ȡ��Կ�б��й���֤������
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
     * ����RSA֤�飬���ز�����cert��
     */
    public static Object[] getRsaCert(String strpath) {
        ArrayList<X509Certificate> cert = ParseCert.getCert(strpath, "RSA");
        return cert.toArray(new Object[0]);
    }

    /*
     * ����SM2֤�飬���ز�����cert��
     */
    public static Object[] getSM2Cert(String strpath) {
        ArrayList<X509Certificate> cert = ParseCert.getCert(strpath, "SM2");
        return cert.toArray(new Object[0]);
    }

    /*
     * �ϲ�RSA��SM2֤�飬���ز�����X509Certificate cert��
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
     * ����֤��·�������ͽ�����ȡ֤�� keyTpye = sm2 ��ȡ����֤�� keyTpye = rsa ��ȡRSA֤�� keyTpye = all
     * ��ȡ��������֤��
     *
     * @param strpath ֤����·��
     * @param keyType ֤������
     */
    public static Object[] getCert(String strpath, String keyType) {
        ArrayList<X509Certificate> cert = ParseCert.getCert(strpath, keyType);

        return cert.toArray(new Object[0]);
    }

    /*
     * ��ȡ��Կ�б�������֤���dn
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
     * ��ȡ����ժҪ�㷨
     */
    public static Object[] getAlg() {
        String[] rsaAlg = RSAHashArrays();
        String[] sm3Alg = SM3HashArrays();
        int rsaSize = rsaAlg.length;
        int sm3Size = sm3Alg.length;
        List<String> list = new ArrayList<>();
        // rsaժҪ�㷨����
        rsaAlg = Arrays.copyOf(rsaAlg, rsaSize + sm3Size);
        // ����sm3ժҪ�㷨�������ݵ�rsaժҪ�㷨����
        System.arraycopy(sm3Alg, 0, rsaAlg, rsaSize, sm3Size);
        for (String s : rsaAlg) {
            if (!list.contains(s)) {
                list.add(s);
            }
        }
        return list.toArray(new String[0]);
    }
//===========================================facePayment1.3����======================================================

    /**
     * ����Ϊnull��""
     */
    public static String[] Emptys() {
        List<String> emptylist = new ArrayList<>();
        emptylist.add("");
        emptylist.add(null);
        return emptylist.toArray(new String[0]);
    }

    /**
     * ��ȡ���жԳ��㷨
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
     * ��ȡ�Գ���Կ����Կ���� ivEmpty = true �����غ���/ECB�����ģʽ��RC4/RC2�Գ���Կ�㷨
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
                Assert.fail("===����ȷ����IV����===");
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
                Assert.fail("===����ȷ����IV����===");
                return null;
            }
        }
        return list.toArray(new String[0]);
    }

    /**
     * ��ȡ�Գ���Կ�㷨���ģʽ
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
     * ����iv������϶Գ���Կ�����ģʽ
     *
     * @param ivLength iv����
     * @param ivEmpty  iv�Ƿ�Ϊ�� ��ivEmpty = true �����غ���/ECB�����ģʽ
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
     * �����Գ���Կ�б��ȡ:keyLable��keyType��keyData
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
                    Assert.fail("����ȷ����iv����");
                }
            }
        } else if (keyLables.length == 0) {
            Assert.fail("����KeyLableԪ�������Ƿ�������ȷ");
        } else if (keyTypes.length == 0) {
            Assert.fail("����KeyTypeԪ�������Ƿ�������ȷ");
        } else {
            Assert.fail("����KeyDataԪ�������Ƿ�������ȷ");
        }
        return list.toArray(new String[0]);
    }

    /**
     * ����iv������϶Գ���Կ�����ģʽ,�Գ���Կ��Ϣ����keyData/keyLable/keyType
     *
     * @param ivLength iv����
     * @param ivEmpty  iv�Ƿ�Ϊ�� ��ivEmpty = true �����غ���/ECB�����ģʽ
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
     * ����iv������϶Գ���Կ���ͼ����ģʽ
     *
     * @param ivLength iv����
     * @param ivEmpty  iv�Ƿ�Ϊ�� ��ivEmpty = true �����غ���/ECB�����ģʽ
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
     * ��϶Գ���Կ��֤��DN,�Գ���Կ��Ϣ����keyData/keyLable/keyType ivLength = 0 �����������ͶԳ���Կ ivLength
     * = 8 ��������Ϊ3DES/DES�Գ���Կ ivLength = 16 ��������ΪAES/SM4�Գ���Կ
     *
     * @param ivLength iv����
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
     * �ǶԳƼ������ģʽ
     */
    public static Object[] asymmModeAndPadding() {
        List<String> list = new ArrayList<>();
        list.add("RSA");
        list.add("RSA/ECB/PKCS1Padding");
        return list.toArray(new String[0]);
    }

    /**
     * ��ϷǶԳƼ������ģʽ��֤��DN
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
     * ���֤���Base64�Լ�DN��Ϣ
     *
     * @param attr    ֤����Ϣ��֧��DN��SN��Bankcode
     * @param strpath ֤��·��
     * @param keyType ֤������
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
     * ���֤���Base64�Լ�BankCode��Ϣ(֤���base64��BankCodeʵ��δ��Ӧ)
     *
     * @param strpath ֤��·��
     * @param keyType ֤������
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
     * ����֤��·�����������֤����Ϣ��Base64��Ϣ���ԳƼ����㷨
     *
     * @param strpath ֤��·��
     * @param keyType ֤������all��������֤�飬sm2���ع���֤�飬rsa����RSA֤��
     * @param length  length=0�������жԳƼ����㷨�� length=8����des/3des/rc2/rc4�ԳƼ����㷨��
     *                length=16����aes/sm4�ԳƼ����㷨
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
                Assert.fail("����ȷ����ժҪ�㷨����");
                break;
        }
        return strings;
    }

    /**
     * ��ȡRSA��SM2֤��SN�������Ӧ��ժҪ�㷨
     *
     * @param strpath ֤��·��
     * @return [alg, sn]
     */
    public static Object[][] resolveAlgSN(String strpath) {
        // ����RSA֤�飬���RSA����Դ
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

        // ��������֤�飬���SM2����Դ
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

        // �ϲ�RSA��SM2
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
     * ��ȡRSA��SM2֤��DN��ժҪ�㷨����Կ֤��
     *
     * @param strpath ֤��·��
     * @return [alg, dn , cert]
     */
    public static Object[][] resolveAlgDNCert(String strpath) {
        // ����RSA֤�飬���RSA����Դ
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

        // ��������֤�飬���SM2����Դ
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

        // �ϲ�RSA��SM2
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
     * ���������������֤�����Ժ�ժҪ�㷨���Գ��㷨
     *
     * @param attr     ֤�����ԣ�֧�ַ���DN��SN��BankCode
     * @param isDalg   �Ƿ����ժҪ�㷨
     * @param isSalg   �Ƿ���϶Գ��㷨
     * @param certpath ֤��·��
     * @param type     ֤�顢ժҪ�㷨���ͣ�RSA��SM2
     * @param length   �Գ��㷨�鳤�ȣ�length=0�������жԳƼ����㷨��
     *                 length=8����des/3des/rc2/rc4�ԳƼ����㷨��
     *                 length=16����aes/sm4�ԳƼ����㷨
     */
    public static Object[][] composeCertAttrWithAlg(String attr, boolean isDalg, boolean isSalg,
                                                    String certpath, String type, int length) {
        String[] certStrs;
        String[] dAlgs;
        String[] sAlgs;
        // ���֤�����Լ�ժҪ�㷨�Գ��㷨
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
        // ���֤�����Լ�ժҪ�㷨
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
        // ���֤�����Լ��Գ��㷨
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
        // ������֤������
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
        // ������ժҪ�㷨
        if (attr == null && isDalg) {
            dAlgs = getHashByType(type);
            int size = dAlgs.length;
            Object[][] tmp = new Object[size][];

            for (String dAlg : dAlgs) {
                tmp[--size] = new Object[]{dAlg};
            }
            return tmp;
        }

        // �����ضԳ��㷨
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
