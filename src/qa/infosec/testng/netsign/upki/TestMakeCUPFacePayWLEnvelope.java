package qa.infosec.testng.netsign.upki;

import cn.com.infosec.netsign.agent.UpkiAgent;
import cn.com.infosec.netsign.agent.UpkiResult;
import cn.com.infosec.netsign.frame.util.PrivateKeyUtil;
import org.testng.Assert;
import org.testng.Reporter;
import org.testng.annotations.Test;
import qa.infosec.testng.netsign.dataprovider.NetSignDataProvider;
import qa.infosec.testng.netsign.dataprovider.util.*;
import qa.infosec.testng.netsign.init.NetSignServerInit;

import java.util.Map;

/**
 * @author zhaoyongzhi
 * @ClassName: TestMakeCUPFacePayWLEnvelope
 * @date 2020-03-02 18:21
 * @Description: ˢ��֧�����������ŷ�
 * <p>�������ǵ㣺</p>
 * <p>1������ˢ��֧�������ŷ�,�Գ���Կ����ΪSM4/AES</p>
 * <p>2������ˢ��֧�������ŷ�,�Գ���Կ����Ϊ3DES/DES</p>
 * <p>3��pinCryptoΪnull,�㷨����ΪSM4/AES</p>
 * <p>4��pinCryptoΪnull,�㷨����Ϊ3DES/DES</p>
 * <p>5��pinCrypto���Ĵ۸�,�Գ���Կ����SM4/AES</p>
 * <p>6��pinCrypto���Ĵ۸ģ��Գ���Կ����3DES/DES</p>
 * <p>7��ivΪnull,���ģʽΪ/ECB</p>
 * <p>8��ivΪnull,���ģʽΪ/CBC/CFB/OFB</p>
 * <p>9��iv ���ȴ���</p>
 * <p>10��iv �۸�</p>
 * <p>11��iv ����pin��������IV�����������������IV��һ��</p>
 * <p>12��pinModeAndPadding �����ʱʹ�õ����ģʽ��ƥ��</p>
 * <p>13��pinModeAndPadding ����Ϊ��</p>
 * <p>14��pinModeAndPadding ����Ϊnull</p>
 * <p>15��pinModeAndPadding �������ֵ</p>
 * <p>16��pinModeAndPadding ���ݴ���</p>
 * <p>17��noPaddingSecret ���貹λ���������ݣ����ȷ��㷨���鳤�����������㷨����ΪDES/3DES</p>
 * <p>18��noPaddingSecret ���貹λ���������ݣ����ȷ��㷨���鳤�����������㷨����ΪAES/SM4</p>
 * <p>19��noPaddingSecret ����Ϊnull</p>
 * <p>20��paddingSecret ���ȷ��㷨���鳤�����������㷨����Ϊ3DES/DES</p>
 * <p>21��paddingSecret ���ȷ��㷨���鳤�����������㷨����ΪAES/SM4</p>
 * <p>22��paddingSecret ����Ϊnull</p>
 * <p>23��paddingSecret ���ȷ��㷨���鳤��������,���ģʽΪ/CBC/NoPadding</p>
 * <p>24��modeAndPadding �������ģʽΪ��</p>
 * <p>25��modeAndPadding �������ģʽΪnull</p>
 * <p>26��encDN ��ȷDN���Գ��㷨����ΪDES/3DES</p>
 * <p>27��encDN ��ȷDN���Գ��㷨����ΪAES/SM4</p>
 * <p>28��encDN DN������</p>
 * <p>29��encDN DNΪ��</p>
 * <p>30��encDN DNΪnull</p>
 */
@Test(groups = "abcjew.makecupfacepaywlenvelope")
public class TestMakeCUPFacePayWLEnvelope {
    static String ip, port, password;
    static String host, sftp_port, sftp_password, sftp_user;

    NetSignServerInit init = new NetSignServerInit();
    UpkiAgent agent;
    SFTPFile tmp = new SFTPFile();
    UtilsAgent2G utils;

    {
        Map<String, String> map = ParseFile.parseProperties(null);
        ip = map.get("ServerIP");
        port = map.get("ServerPortPBC2G");
        password = map.get("APIPassword");

        host = map.get("sftp_ip");
        sftp_port = map.get("sftp_port");
        sftp_user = map.get("sftp_user");
        sftp_password = map.get("sftp_password");

        agent = init.upkiStart(ip, port, password, true, 20);
        utils = init.utilsStart(ip, port, password);
        tmp.downFile(sftp_user, host, sftp_port, sftp_password, ParameterUtil.sftpsymmpath,
                ParameterUtil.localsymmpath);
        System.out.println("NetSignServerInit OK");
    }

    /**
     * ˢ��֧�����������ŷ⣺�Գ��㷨ʹ��SM4/AES
     *
     * @param modeAndPadding ���ģʽ
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_01(String keyLableAndTypeAndData, String modeAndPadding) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // ��ȡ�Գ���Կdata�����ܶԳ���Կ
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // ʹ�öԳ���Կ��pin���ܣ��õ�pin����
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // �������pin���ĵ�pinCrypto[][]����
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // ������貹λ����������
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();
        // �����Ҫ��λ����������
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("ˢ��֧�����������ŷ⣺�Գ��㷨ʹ��SM4/AES��ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ����ˢ��֧�������ŷ⣺�Գ���Կ����ΪDES/3DES
     *
     * @param modeAndPadding ���ģʽ
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-8-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_02(String keyLableAndTypeAndData, String modeAndPadding) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(8).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // ��ȡ�Գ���Կdata�����ܶԳ���Կ
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // ʹ�öԳ���Կ��pin���ܣ��õ�pin����
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // �������pin���ĵ�pinCrypto[][]����
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // ������貹λ����������
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();
        // �����Ҫ��λ����������
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(8).getBytes();
        paddingSecret[1] = Utils.getRandomString(8).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -100112) {
                    Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("����ˢ��֧�������ŷ�(makeCUPFacePayWLEnvelope)����֧��DES");
            }
            System.out.println("ˢ��֧�����������ŷ⣺�Գ���Կ����ΪDES/3DES��ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ����ˢ��֧�������ŷ⣺pinCryptoΪnull,�㷨����ΪSM4/AES
     *
     * @param modeAndPadding ���ģʽ
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "alg-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_03(String keyType, String modeAndPadding) {

        byte[] iv = Utils.getRandomString(16).getBytes();
        String pinModeAndPadding = keyType + modeAndPadding;
        String encDn = "O=infosec,CN=sm2_rev";

        // ������貹λ����������
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();
        // �����Ҫ��λ����������
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(null, null, null, null,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("ˢ��֧�����������ŷ⣺pinCryptoΪnull,�㷨����ΪSM4/AES��ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ����ˢ��֧�������ŷ⣺pinCryptoΪnull,�㷨����Ϊ3DES/DES
     *
     * @param modeAndPadding ���ģʽ
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "alg-8-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_04(String keyType, String modeAndPadding) {

        byte[] iv = Utils.getRandomString(8).getBytes();
        String pinModeAndPadding = keyType + modeAndPadding;
        String encDn = "O=infosec,CN=sm2_rev";

        // ������貹λ����������
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();
        // �����Ҫ��λ����������
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(8).getBytes();
        paddingSecret[1] = Utils.getRandomString(8).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(null, null, null, null,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -100112) {
                    Assert.fail("����ˢ��֧�������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("����ˢ��֧�������ŷ�(makeCUPFacePayWLEnvelope)����֧��DES/RC2/RC4");
            }
            System.out.println("ˢ��֧�����������ŷ⣺pinCryptoΪnull,�㷨����ΪSM4/AES��ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺pinCrypto���Ĵ۸�,�Գ���Կ����SM4/AES
     *
     * @param modeAndPadding ���ģʽ
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_05(String keyLableAndTypeAndData, String modeAndPadding) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // ��ȡ�Գ���Կdata�����ܶԳ���Կ
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // ʹ�öԳ���Կ��pin���ܣ��õ�pin����
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // �������pin���ĵ�pinCrypto[][]����
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            //�۸�pin����
            pinCry_01[0] = Utils.modifyData(pinCry_01[0], 5, 10, "abcde");
            pinCry_02[0] = Utils.modifyData(pinCry_02[0], 5, 10, "abcde");
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // ������貹λ����������
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();
        // �����Ҫ��λ����������
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("ˢ��֧�����������ŷ⣺pinCrypto���Ĵ۸�,�Գ���Կ����SM4/AES��ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺pinCrypto���Ĵ۸ģ��Գ���Կ����3DES/DES
     *
     * @param modeAndPadding ���ģʽ
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-8-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_06(String keyLableAndTypeAndData, String modeAndPadding) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(8).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // ��ȡ�Գ���Կdata�����ܶԳ���Կ
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // ʹ�öԳ���Կ��pin���ܣ��õ�pin����
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // �������pin���ĵ�pinCrypto[][]����
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            //�۸�pin����
            pinCry_01[0] = Utils.modifyData(pinCry_01[0], 5, 10, "abcde");
            pinCry_02[0] = Utils.modifyData(pinCry_02[0], 5, 10, "abcde");
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // ������貹λ����������
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();
        // �����Ҫ��λ����������
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(8).getBytes();
        paddingSecret[1] = Utils.getRandomString(8).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -100112) {
                    Assert.fail("����ˢ��֧�������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("����ˢ��֧�������ŷ�(makeCUPFacePayWLEnvelope)����֧��DES");
            }
            System.out.println("ˢ��֧�����������ŷ⣺pinCrypto���Ĵ۸ģ��Գ���Կ����3DES/DES��ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺ivΪnull,���ģʽΪ/ECB
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-0",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_07(String keyLableAndTypeAndData) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = null;
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String modeAndPadding = "/ECB/PKCS7Padding";
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // ��ȡ�Գ���Կdata�����ܶԳ���Կ
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // ʹ�öԳ���Կ��pin���ܣ��õ�pin����
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // �������pin���ĵ�pinCrypto[][]����
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // ������貹λ����������
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();
        // �����Ҫ��λ����������
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -100112) {
                    Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("����ˢ��֧�������ŷ�(makeCUPFacePayWLEnvelope):���ģʽΪ/ECBʱ����֧��DES");
            }
            System.out.println("ˢ��֧�����������ŷ⣺ivΪnull,���ģʽΪ/ECB��ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺ivΪnull,���ģʽΪ/CBC/CFB/OFB
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-0-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_08(String keyLableAndTypeAndData, String modeAndPadding) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = null;
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // ��ȡ�Գ���Կdata�����ܶԳ���Կ
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // ʹ�öԳ���Կ��pin���ܣ��õ�pin����
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // �������pin���ĵ�pinCrypto[][]����
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // ������貹λ����������
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();
        // �����Ҫ��λ����������
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != -1022) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("ˢ��֧�����������ŷ⣺ivΪnull,���ģʽΪ/CBC/CFB/OFB��ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺iv ���ȴ���
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-0-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_09(String keyLableAndTypeAndData, String modeAndPadding) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(7).getBytes();
        byte[] iv2 = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // ��ȡ�Գ���Կdata�����ܶԳ���Կ
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // ʹ�öԳ���Կ��pin���ܣ��õ�pin����
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv2, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv2, keyType, modeAndPadding);
//            if (utils.getReturnCode() != 1) {
//                Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
//            }
        } catch (Exception e) {
            Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // �������pin���ĵ�pinCrypto[][]����
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // ������貹λ����������
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();
        // �����Ҫ��λ����������
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != -100110 && upkiResult.getReturnCode() != -100010) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("ˢ��֧�����������ŷ⣺iv ���ȴ���ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺iv�۸�
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_10(String keyLableAndTypeAndData, String modeAndPadding) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] iv2 = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // ��ȡ�Գ���Կdata�����ܶԳ���Կ
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // ʹ�öԳ���Կ��pin���ܣ��õ�pin����
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // �������pin���ĵ�pinCrypto[][]����
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // ������貹λ����������
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();
        // �����Ҫ��λ����������
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv2,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != -100110) {
                if (upkiResult.getReturnCode() != 0) {
                    Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("����ˢ��֧�������ŷ�(makeCUPFacePayWLEnvelope):����PIN��������IV�۸����ܽ��ܳɹ�");
            }
            System.out.println("ˢ��֧�����������ŷ⣺iv ���ȴ���ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺iv ����pin��������IV�����������������IV��һ��
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_11(String keyLableAndTypeAndData, String modeAndPadding) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] iv2 = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // ��ȡ�Գ���Կdata�����ܶԳ���Կ
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // ʹ�öԳ���Կ��pin���ܣ��õ�pin����
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // �������pin���ĵ�pinCrypto[][]����
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // ������貹λ����������
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();
        // �����Ҫ��λ����������
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv2, encDn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("ˢ��֧�����������ŷ⣺iv ����pin��������IV�����������������IV��һ������,ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺pinModeAndPadding �����ʱʹ�õ����ģʽ��ƥ��
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-8-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_12(String keyLableAndTypeAndData, String modeAndPadding) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(8).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // ��ȡ�Գ���Կdata�����ܶԳ���Կ
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // ʹ�öԳ���Կ��pin���ܣ��õ�pin����
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // �������pin���ĵ�pinCrypto[][]����
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // ������貹λ����������
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();
        // �����Ҫ��λ����������
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            String modePadding = "/ECB/NoPadding";
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -100112) {
                    Assert.fail("����ˢ��֧�������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("����ˢ��֧�������ŷ�(makeCUPFacePayWLEnvelope):��֧�ֶԳ��㷨DES");
            }
            System.out.println("ˢ��֧�����������ŷ⣺pinModeAndPadding �����ʱʹ�õ����ģʽ��ƥ������,ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺pinModeAndPadding ����Ϊ��
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_13(String keyLableAndTypeAndData, String modeAndPadding) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // ��ȡ�Գ���Կdata�����ܶԳ���Կ
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // ʹ�öԳ���Կ��pin���ܣ��õ�pin����
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // �������pin���ĵ�pinCrypto[][]����
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // ������貹λ����������
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();
        // �����Ҫ��λ����������
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, "", iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != -100110) {
                Assert.fail("����ˢ��֧�������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("ˢ��֧�����������ŷ⣺pinModeAndPadding ����Ϊ������,ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺pinModeAndPadding ����Ϊnull
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_14(String keyLableAndTypeAndData, String modeAndPadding) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // ��ȡ�Գ���Կdata�����ܶԳ���Կ
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // ʹ�öԳ���Կ��pin���ܣ��õ�pin����
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // �������pin���ĵ�pinCrypto[][]����
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // ������貹λ����������
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();
        // �����Ҫ��λ����������
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, null, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != -100110) {
                Assert.fail("����ˢ��֧�������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("ˢ��֧�����������ŷ⣺pinModeAndPadding ����Ϊnull����,ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺pinModeAndPadding ���ݴ���
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_15(String keyLableAndTypeAndData, String modeAndPadding) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // ��ȡ�Գ���Կdata�����ܶԳ���Կ
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // ʹ�öԳ���Կ��pin���ܣ��õ�pin����
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // �������pin���ĵ�pinCrypto[][]����
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // ������貹λ����������
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();
        // �����Ҫ��λ����������
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, "ABC", iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != -100110) {
                Assert.fail("����ˢ��֧�������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("ˢ��֧�����������ŷ⣺pinModeAndPadding ���ݴ�������,ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺pinModeAndPadding ���ݴ���
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_16(String keyLableAndTypeAndData, String modeAndPadding) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // ��ȡ�Գ���Կdata�����ܶԳ���Կ
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // ʹ�öԳ���Կ��pin���ܣ��õ�pin����
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // �������pin���ĵ�pinCrypto[][]����
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // ������貹λ����������
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();
        // �����Ҫ��λ����������
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, "ABC", iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != -100110) {
                Assert.fail("����ˢ��֧�������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("ˢ��֧�����������ŷ⣺pinModeAndPadding ���ݴ�������,ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺noPaddingSecret,���貹λ���������ݣ����ȷ��㷨���鳤��������
     *
     * @param keyLableAndTypeAndData �����㷨����Ϊ3DES/DES
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-8",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_17(String keyLableAndTypeAndData) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(8).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String modeAndPadding = "/CBC/PKCS7Padding";
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // ��ȡ�Գ���Կdata�����ܶԳ���Կ
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // ʹ�öԳ���Կ��pin���ܣ��õ�pin����
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // �������pin���ĵ�pinCrypto[][]����
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // ������貹λ����������
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(17).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(17).getBytes();
        // �����Ҫ��λ����������
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != -100116) {
                if (upkiResult.getReturnCode() != -100112) {
                    Assert.fail("����ˢ��֧�������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("����ˢ��֧�������ŷ�(makeCUPFacePayWLEnvelope):�ԳƼ����㷨��֧��DES");
            }
            System.out.println("ˢ��֧�����������ŷ⣺noPaddingSecret,���貹λ���������ݣ����ȷ��㷨���鳤������������,ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺noPaddingSecret,���貹λ���������ݣ����ȷ��㷨���鳤��������
     *
     * @param keyLableAndTypeAndData �����㷨����ΪAES/SM4
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_18(String keyLableAndTypeAndData) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String modeAndPadding = "/CBC/PKCS7Padding";
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // ��ȡ�Գ���Կdata�����ܶԳ���Կ
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // ʹ�öԳ���Կ��pin���ܣ��õ�pin����
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // �������pin���ĵ�pinCrypto[][]����
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // ������貹λ����������
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(17).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(17).getBytes();
        // �����Ҫ��λ����������
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != -100116) {
                Assert.fail("����ˢ��֧�������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("ˢ��֧�����������ŷ⣺noPaddingSecret,���貹λ���������ݣ����ȷ��㷨���鳤������������,ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺noPaddingSecret ����Ϊnull
     *
     * @param keyLableAndTypeAndData �����㷨����Ϊ3DES/DES
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_19(String keyLableAndTypeAndData) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String modeAndPadding = "/CBC/PKCS7Padding";
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // ��ȡ�Գ���Կdata�����ܶԳ���Կ
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // ʹ�öԳ���Կ��pin���ܣ��õ�pin����
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // �������pin���ĵ�pinCrypto[][]����
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // ������貹λ����������
        byte[][] noPaddingSecret = null;

        // �����Ҫ��λ����������
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("����ˢ��֧�������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("ˢ��֧�����������ŷ⣺noPaddingSecret ����Ϊnull����,ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺paddingSecret ���ȷ��㷨���鳤��������
     *
     * @param keyLableAndTypeAndData �����㷨����Ϊ3DES/DES
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-8",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_20(String keyLableAndTypeAndData) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(8).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String modeAndPadding = "/CBC/PKCS7Padding";
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // ��ȡ�Գ���Կdata�����ܶԳ���Կ
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // ʹ�öԳ���Կ��pin���ܣ��õ�pin����
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // �������pin���ĵ�pinCrypto[][]����
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // ������貹λ����������
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();

        // �����Ҫ��λ����������
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(4).getBytes();
        paddingSecret[1] = Utils.getRandomString(5).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -100112) {
                    Assert.fail("����ˢ��֧�������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("����ˢ��֧�������ŷ�(makeCUPFacePayWLEnvelope):�ԳƼ����㷨��֧��DES");
            }
            System.out.println("ˢ��֧�����������ŷ⣺paddingSecret ���ȷ��㷨���鳤��������,ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺paddingSecret ���ȷ��㷨���鳤��������
     *
     * @param keyLableAndTypeAndData �����㷨����ΪAES/SM4
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_21(String keyLableAndTypeAndData) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String modeAndPadding = "/CBC/PKCS7Padding";
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // ��ȡ�Գ���Կdata�����ܶԳ���Կ
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // ʹ�öԳ���Կ��pin���ܣ��õ�pin����
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // �������pin���ĵ�pinCrypto[][]����
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // ������貹λ����������
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();

        // �����Ҫ��λ����������
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(4).getBytes();
        paddingSecret[1] = Utils.getRandomString(5).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("����ˢ��֧�������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("ˢ��֧�����������ŷ⣺paddingSecret ���ȷ��㷨���鳤������������,ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺paddingSecret ����Ϊnull���㷨����ΪAES/SM4
     *
     * @param keyLableAndTypeAndData �����㷨����ΪAES/SM4
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_22(String keyLableAndTypeAndData) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String modeAndPadding = "/CBC/PKCS7Padding";
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // ��ȡ�Գ���Կdata�����ܶԳ���Կ
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // ʹ�öԳ���Կ��pin���ܣ��õ�pin����
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // �������pin���ĵ�pinCrypto[][]����
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // ������貹λ����������
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();

        // �����Ҫ��λ����������
        byte[][] paddingSecret = null;

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("����ˢ��֧�������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("ˢ��֧�����������ŷ⣺paddingSecret ����Ϊnull���㷨����ΪAES/SM4����,ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺paddingSecret���ȷ��㷨���鳤��������,���ģʽΪ/CBC/NoPadding
     *
     * @param keyLableAndTypeAndData �����㷨����ΪAES/SM4
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_23(String keyLableAndTypeAndData) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String modeAndPadding = "/CBC/NoPadding";
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // ��ȡ�Գ���Կdata�����ܶԳ���Կ
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // ʹ�öԳ���Կ��pin���ܣ��õ�pin����
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // �������pin���ĵ�pinCrypto[][]����
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // ������貹λ����������
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();

        // �����Ҫ��λ����������
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(6).getBytes();
        paddingSecret[1] = Utils.getRandomString(6).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -100116) {
                    Assert.fail("����ˢ��֧�������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("����ˢ��֧�������ŷ�(makeCUPFacePayWLEnvelope):�������ģʽΪ/CBC/NoPaddingʱ����Ҫ��λ���������ݳ���Ҳ��Ҫ���㷨���鳤��һ��");
            }
            System.out.println("ˢ��֧�����������ŷ⣺paddingSecret���ȷ��㷨���鳤��������,���ģʽΪ/CBC/NoPadding����,ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺modeAndPadding �������ģʽΪ��
     *
     * @param keyLableAndTypeAndData �����㷨����ΪAES/SM4
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_24(String keyLableAndTypeAndData) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String modeAndPadding = "/CBC/NoPadding";
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // ��ȡ�Գ���Կdata�����ܶԳ���Կ
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // ʹ�öԳ���Կ��pin���ܣ��õ�pin����
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // �������pin���ĵ�pinCrypto[][]����
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // ������貹λ����������
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();

        // �����Ҫ��λ����������
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, "", iv, encDn);
            if (upkiResult.getReturnCode() != -1022) {
                Assert.fail("����ˢ��֧�������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("ˢ��֧�����������ŷ⣺modeAndPadding �������ģʽΪ������,ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺modeAndPadding �������ģʽΪnull
     *
     * @param keyLableAndTypeAndData �����㷨����ΪAES/SM4
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_25(String keyLableAndTypeAndData) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String modeAndPadding = "/CBC/NoPadding";
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "O=infosec,CN=sm2_rev";

        // ��ȡ�Գ���Կdata�����ܶԳ���Կ
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // ʹ�öԳ���Կ��pin���ܣ��õ�pin����
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // �������pin���ĵ�pinCrypto[][]����
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // ������貹λ����������
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();

        // �����Ҫ��λ����������
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, null, iv, encDn);
            if (upkiResult.getReturnCode() != -1022) {
                Assert.fail("����ˢ��֧�������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("ˢ��֧�����������ŷ⣺modeAndPadding �������ģʽΪ������,ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺encDN ��ȷDN
     *
     * @param keyLableAndTypeAndData �����㷨����ΪDES/3DES
     * @param encDn                  ����dn
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "symmkey-8-dn",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_26(String keyLableAndTypeAndData, String encDn) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(8).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String modeAndPadding = "/CBC/PKCS7Padding";
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;

        // ��ȡ�Գ���Կdata�����ܶԳ���Կ
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // ʹ�öԳ���Կ��pin���ܣ��õ�pin����
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // �������pin���ĵ�pinCrypto[][]����
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // ������貹λ����������
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();

        // �����Ҫ��λ����������
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -100112) {
                    Assert.fail("����ˢ��֧�������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("����ˢ��֧�������ŷ�(makeCUPFacePayWLEnvelope)����֧��DES");
            }
            System.out.println("ˢ��֧�����������ŷ⣺encDN ��ȷDN����,ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺encDN ��ȷDN
     *
     * @param keyLableAndTypeAndData �����㷨����ΪAES/SM4
     * @param encDn                  ����dn
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "symmkey-16-dn",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_27(String keyLableAndTypeAndData, String encDn) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String modeAndPadding = "/CBC/PKCS7Padding";
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;

        // ��ȡ�Գ���Կdata�����ܶԳ���Կ
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // ʹ�öԳ���Կ��pin���ܣ��õ�pin����
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // �������pin���ĵ�pinCrypto[][]����
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // ������貹λ����������
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();

        // �����Ҫ��λ����������
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("����ˢ��֧�������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("ˢ��֧�����������ŷ⣺encDN ��ȷDN����,ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺encDN,DN������
     *
     * @param keyLableAndTypeAndData �����㷨����ΪAES/SM4
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_28(String keyLableAndTypeAndData) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String modeAndPadding = "/CBC/PKCS7Padding";
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "CN=123";

        // ��ȡ�Գ���Կdata�����ܶԳ���Կ
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // ʹ�öԳ���Կ��pin���ܣ��õ�pin����
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // �������pin���ĵ�pinCrypto[][]����
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // ������貹λ����������
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();

        // �����Ҫ��λ����������
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != -100203) {
                Assert.fail("����ˢ��֧�������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("ˢ��֧�����������ŷ⣺encDN,DN����������,ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺encDN,DNΪ��
     *
     * @param keyLableAndTypeAndData �����㷨����ΪAES/SM4
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_29(String keyLableAndTypeAndData) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String modeAndPadding = "/CBC/PKCS7Padding";
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = "";

        // ��ȡ�Գ���Կdata�����ܶԳ���Կ
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // ʹ�öԳ���Կ��pin���ܣ��õ�pin����
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // �������pin���ĵ�pinCrypto[][]����
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // ������貹λ����������
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();

        // �����Ҫ��λ����������
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != -1022) {
                Assert.fail("����ˢ��֧�������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("ˢ��֧�����������ŷ⣺encDN,DNΪ������,ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺encDN,DNΪnull
     *
     * @param keyLableAndTypeAndData �����㷨����ΪAES/SM4
     */
    @Test(groups = "abcjew.makecupfacepaywlenvelope", dataProvider = "keylable-type-data-16",
            dataProviderClass = NetSignDataProvider.class)
    public void testMakeCUPFacePayWLEnvelope_30(String keyLableAndTypeAndData) {

        String[] strs = keyLableAndTypeAndData.split("&");
        String keyLable = strs[0];
        String keyType = strs[1];
        String keyData = strs[2];
        String password = keyLable + keyType;
        byte[] pinText_01 = Utils.getRandomString(32).getBytes();
        byte[] pinText_02 = Utils.getRandomString(32).getBytes();
        byte[] iv = Utils.getRandomString(16).getBytes();
        byte[] privateKey = null;
        byte[][] pinCrypto = null;
        String modeAndPadding = "/CBC/PKCS7Padding";
        String pinModeAndPadding = keyType + modeAndPadding;
        byte[][] pinCry_01 = null;
        byte[][] pinCry_02 = null;
        String encDn = null;

        // ��ȡ�Գ���Կdata�����ܶԳ���Կ
        try {
            privateKey = PrivateKeyUtil.decryptPrivateKey(keyData, password);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        // ʹ�öԳ���Կ��pin���ܣ��õ�pin����
        try {
            pinCry_01 = utils.symmEncrypt(pinText_01, privateKey, iv, keyType, modeAndPadding);
            pinCry_02 = utils.symmEncrypt(pinText_02, privateKey, iv, keyType, modeAndPadding);
            if (utils.getReturnCode() != 1) {
                Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
            }
        } catch (Exception e) {
            Assert.fail("�Գ���Կ��pin����ʧ�ܣ�" + utils.getReturnCode() + utils.getErrorMsg());
        }

        // �������pin���ĵ�pinCrypto[][]����
        if (pinCry_01 != null && pinCry_02 != null) {
            pinCrypto = new byte[2][];
            pinCrypto[0] = pinCry_01[0];
            pinCrypto[1] = pinCry_02[0];
        }
        // ������貹λ����������
        byte[][] noPaddingSecret = new byte[2][];
        noPaddingSecret[0] = Utils.getRandomString(16).getBytes();
        noPaddingSecret[1] = Utils.getRandomString(16).getBytes();

        // �����Ҫ��λ����������
        byte[][] paddingSecret = new byte[2][];
        paddingSecret[0] = Utils.getRandomString(16).getBytes();
        paddingSecret[1] = Utils.getRandomString(16).getBytes();

        try {
            UpkiResult upkiResult = agent.makeCUPFacePayWLEnvelope(pinCrypto, keyLable, pinModeAndPadding, iv,
                    noPaddingSecret, paddingSecret, pinModeAndPadding, iv, encDn);
            if (upkiResult.getReturnCode() != -1022) {
                Assert.fail("����ˢ��֧�������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            System.out.println("ˢ��֧�����������ŷ⣺encDN,DNΪ������,ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }
}
