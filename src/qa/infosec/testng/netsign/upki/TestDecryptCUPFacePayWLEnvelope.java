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

import java.io.IOException;
import java.util.Map;

/**
 * @author zhaoyongzhi
 * @ClassName: TestDecryptCUPFacePayWLEnvelope
 * @date 2020-04-30 14:21
 * @Description: ˢ��֧�����������ŷ�
 * <p>�������ǵ㣺</p>
 * <p>1��ˢ��֧�����������ŷ⣺�Գ���Կ����ΪSM4/AES</p>
 * <p>2��ˢ��֧�����������ŷ⣺�Գ���Կ����Ϊ3DES/DES</p>
 * <p>3��ˢ��֧�����������ŷ⣺crypto ��������Ϊ��</p>
 * <p>4��ˢ��֧�����������ŷ⣺crypto���Ĵ۸�</p>
 * <p>5��ˢ��֧�����������ŷ⣺encPinKeyLabel ������Կ��Ϊnull</p>
 * <p>6��ˢ��֧�����������ŷ⣺encPinKeyLabel ������Կ��Ϊ��</p>
 * <p>7��ˢ��֧�����������ŷ⣺encPinKeyLabel ������Կ�Ų�����</p>
 * <p>8��ˢ��֧�����������ŷ⣺pinModeAndPadding ����pin��Ҫ�����ģʽΪnull</p>
 * <p>9��ˢ��֧�����������ŷ⣺pinModeAndPadding ����pin��Ҫ�����ģʽΪ��</p>
 * <p>10��ˢ��֧�����������ŷ⣺pinModeAndPadding ����pin��Ҫ�����ģʽ���ݴ���</p>
 * <p>11��ˢ��֧�����������ŷ⣺pinIv ����pinIv�����ʱ��һ��</p>
 * <p>12��ˢ��֧�����������ŷ⣺pinIv ����pinIvΪnull</p>
 * <p>13��ˢ��֧�����������ŷ⣺modeAndPadding �����������ݵ����ģʽ��Ϊ��</p>
 * <p>14��ˢ��֧�����������ŷ⣺modeAndPadding �����������ݵ����ģʽ��Ϊnull</p>
 * <p>15��ˢ��֧�����������ŷ⣺modeAndPadding �����������ݵ����ģʽ�����ݴ���</p>
 * <p>16��ˢ��֧�����������ŷ⣺iv ��������������������������Ϊnull</p>
 * <p>17��ˢ��֧�����������ŷ⣺iv �����������������������۸�</p>
 * <p>18��ˢ��֧�����������ŷ⣺decDN ��ȷDN,�Գ���ԿSM4/AES</p>
 * <p>19��ˢ��֧�����������ŷ⣺decDN ��ȷDN,�Գ���Կ3DES/DES</p>
 * <p>20��ˢ��֧�����������ŷ⣺decDN Ϊ��</p>
 * <p>21��ˢ��֧�����������ŷ⣺decDN Ϊnull</p>
 * <p>22��ˢ��֧�����������ŷ⣺decDN ������</p>
 */
@Test(groups = "abcjew.decryptcupfacepaywlenvelope")
public class TestDecryptCUPFacePayWLEnvelope {
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
     * ˢ��֧�����������ŷ⣺�Գ���Կ����ΪSM4/AES
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_01(String keyLableAndTypeAndData, String modeAndPadding) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
        // ���������ŷ�
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, pinModeAndPadding, iv,
                        pinModeAndPadding, iv, encDn);
                if (upkiResult1.getReturnCode() != 0) {
                    Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("ˢ��֧�����������ŷ⣺�Գ���Կ����ΪSM4/AES������ִ�гɹ�");
            } catch (Exception e) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
            }
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺�Գ���Կ����ΪDES/3DES
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "keylable-type-data-8-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_02(String keyLableAndTypeAndData, String modeAndPadding) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -100112) {
                    Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
        // ���������ŷ�
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, pinModeAndPadding, iv,
                        pinModeAndPadding, iv, encDn);
                if (upkiResult1.getReturnCode() != 0) {
                    Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("ˢ��֧�����������ŷ⣺�Գ���Կ����Ϊ3DES/DES������ִ�гɹ�");
            } catch (Exception e) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
            }
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺crypto ��������Ϊ��
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal")
    public void testDecryptCUPFacePayWLEnvelope_03() {
        String keyLable = "ccfccbMasterKey_SM4";
        byte[] iv = Utils.getRandomString(16).getBytes();
        String pinModeAndPadding = "SM4/CBC/NoPadding";
        String encDn = "O=infosec,CN=sm2_rev";
        // ���������ŷ�
        try {
            UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(null, keyLable, pinModeAndPadding, iv,
                    pinModeAndPadding, iv, encDn);
            if (upkiResult1.getReturnCode() != -1022) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
            System.out.println("ˢ��֧�����������ŷ⣺crypto ��������Ϊ��������ִ�гɹ�");
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺crypto���Ĵ۸�
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_04(String keyLableAndTypeAndData, String modeAndPadding) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
        // ���������ŷ�
        if (crypto != null) {
            try {
                for (int i = 0; i < crypto.length; i++) {
                    for (int j = 0; j < crypto[0].length; j++) {
                        crypto[i][j] = Utils.modifyData(crypto[i][j], 2, 5, "abc");
                    }
                }
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, pinModeAndPadding, iv,
                        pinModeAndPadding, iv, encDn);
                if (upkiResult1.getReturnCode() != -100004) {
                    Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("ˢ��֧�����������ŷ⣺crypto���Ĵ۸�������ִ�гɹ�");
            } catch (Exception e) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
            }
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺encPinKeyLabel ������Կ��Ϊnull
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_05(String keyLableAndTypeAndData, String modeAndPadding) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
        // ���������ŷ�
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, null, pinModeAndPadding, iv,
                        pinModeAndPadding, iv, encDn);
                if (upkiResult1.getReturnCode() != -1022) {
                    Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("ˢ��֧�����������ŷ⣺encPinKeyLabel ������Կ��Ϊnull������ִ�гɹ�");
            } catch (Exception e) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
            }
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺encPinKeyLabel ������Կ��Ϊ��
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_06(String keyLableAndTypeAndData, String modeAndPadding) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
        // ���������ŷ�
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, "", pinModeAndPadding, iv,
                        pinModeAndPadding, iv, encDn);
                if (upkiResult1.getReturnCode() != -1022) {
                    Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("ˢ��֧�����������ŷ⣺encPinKeyLabel ������Կ��Ϊ��������ִ�гɹ�");
            } catch (Exception e) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
            }
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺encPinKeyLabel ������Կ�Ų�����
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_07(String keyLableAndTypeAndData, String modeAndPadding) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
        // ���������ŷ�
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, "CN=123", pinModeAndPadding, iv,
                        pinModeAndPadding, iv, encDn);
                if (upkiResult1.getReturnCode() != -100004) {
                    Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("ˢ��֧�����������ŷ⣺encPinKeyLabel ������Կ�Ų�����������ִ�гɹ�");
            } catch (Exception e) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
            }
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺pinModeAndPadding ����pin��Ҫ�����ģʽΪnull
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_08(String keyLableAndTypeAndData, String modeAndPadding) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
        // ���������ŷ�
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, null, iv,
                        pinModeAndPadding, iv, encDn);
                if (upkiResult1.getReturnCode() != -100116) {
                    Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("ˢ��֧�����������ŷ⣺pinModeAndPadding ����pin��Ҫ�����ģʽΪnull������ִ�гɹ�");
            } catch (Exception e) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
            }
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺pinModeAndPadding ����pin��Ҫ�����ģʽΪ��
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_09(String keyLableAndTypeAndData, String modeAndPadding) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
        // ���������ŷ�
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, "", iv,
                        pinModeAndPadding, iv, encDn);
                if (upkiResult1.getReturnCode() != -100116) {
                    Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("ˢ��֧�����������ŷ⣺pinModeAndPadding ����pin��Ҫ�����ģʽΪ��������ִ�гɹ�");
            } catch (Exception e) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
            }
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺pinModeAndPadding ����pin��Ҫ�����ģʽ���ݴ���
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_10(String keyLableAndTypeAndData, String modeAndPadding) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
        // ���������ŷ�
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, "abc", iv,
                        pinModeAndPadding, iv, encDn);
                if (upkiResult1.getReturnCode() != -100116) {
                    Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("ˢ��֧�����������ŷ⣺pinModeAndPadding ����pin��Ҫ�����ģʽ���ݴ���ִ�гɹ�");
            } catch (Exception e) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
            }
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺pinIv ����pinIv�����ʱ��һ��
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_11(String keyLableAndTypeAndData, String modeAndPadding) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
        // ���������ŷ�
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, pinModeAndPadding, iv2,
                        pinModeAndPadding, iv, encDn);
                if (upkiResult1.getReturnCode() != 0) {
                    Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("ˢ��֧�����������ŷ⣺pinModeAndPadding ����pin��Ҫ�����ģʽ���ݴ���ִ�гɹ�");
            } catch (Exception e) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
            }
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺pinIv ����pinIvΪnull
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_12(String keyLableAndTypeAndData, String modeAndPadding) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
        // ���������ŷ�
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, pinModeAndPadding, null,
                        pinModeAndPadding, iv, encDn);
                if (upkiResult1.getReturnCode() != -1022) {
                    Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("ˢ��֧�����������ŷ⣺pinIv ����pinIvΪnull������ִ�гɹ�");
            } catch (Exception e) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
            }
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺modeAndPadding �����������ݵ����ģʽ��Ϊ��
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_13(String keyLableAndTypeAndData, String modeAndPadding) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
        // ���������ŷ�
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, pinModeAndPadding, null,
                        pinModeAndPadding, iv, encDn);
                if (upkiResult1.getReturnCode() != -1022) {
                    Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("ˢ��֧�����������ŷ⣺pinIv ����pinIvΪnull������ִ�гɹ�");
            } catch (Exception e) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
            }
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺modeAndPadding �����������ݵ����ģʽ��Ϊnull
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_14(String keyLableAndTypeAndData, String modeAndPadding) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
        // ���������ŷ�
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, pinModeAndPadding, iv,
                        null, iv, encDn);
                if (upkiResult1.getReturnCode() != -1022) {
                    Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("ˢ��֧�����������ŷ⣺pinIv ����pinIvΪnull������ִ�гɹ�");
            } catch (Exception e) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
            }
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺modeAndPadding �����������ݵ����ģʽ�����ݴ���
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_15(String keyLableAndTypeAndData, String modeAndPadding) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
        // ���������ŷ�
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, pinModeAndPadding, iv,
                        "123asd", iv, encDn);
                if (upkiResult1.getReturnCode() != -100004) {
                    Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("ˢ��֧�����������ŷ⣺modeAndPadding �����������ݵ����ģʽ�����ݴ���������ִ�гɹ�");
            } catch (Exception e) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
            }
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺iv ��������������������������Ϊnull
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_16(String keyLableAndTypeAndData, String modeAndPadding) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
        // ���������ŷ�
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, pinModeAndPadding, iv,
                        pinModeAndPadding, null, encDn);
                if (upkiResult1.getReturnCode() != -1022) {
                    Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("ˢ��֧�����������ŷ⣺iv ��������������������������Ϊnull������ִ�гɹ�");
            } catch (Exception e) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
            }
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺iv �����������������������۸�
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "keylable-type-data-16-modepadding",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_17(String keyLableAndTypeAndData, String modeAndPadding) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
        // ���������ŷ�
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, pinModeAndPadding, iv,
                        pinModeAndPadding, iv2, encDn);
                if (upkiResult1.getReturnCode() != -100123) {
                    if (upkiResult1.getReturnCode() != 0) {
                        Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                    }
                    Reporter.log("ˢ��֧�����������ŷ⣺iv �����������������������۸�,����ִ�гɹ��������ܵõ����ݴ���");
                }
                System.out.println("ˢ��֧�����������ŷ⣺iv �����������������������۸�������ִ�гɹ�");
            } catch (Exception e) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
            }
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺decDN ��ȷDN
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "symmkey-16-dn",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_18(String keyLableAndTypeAndData, String encDn) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
        // ���������ŷ�
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, pinModeAndPadding, iv,
                        pinModeAndPadding, iv, encDn);
                if (upkiResult1.getReturnCode() != 0) {
                    Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("ˢ��֧�����������ŷ⣺decDN ��ȷDN������ִ�гɹ�");
            } catch (Exception e) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
            }
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺decDN ��ȷDN
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "symmkey-8-dn",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_19(String keyLableAndTypeAndData, String encDn) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -100112) {
                    Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                return;
            }
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
        // ���������ŷ�
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, pinModeAndPadding, iv,
                        pinModeAndPadding, iv, encDn);
                if (upkiResult1.getReturnCode() != 0) {
                    Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("ˢ��֧�����������ŷ⣺decDN ��ȷDN������ִ�гɹ�");
            } catch (Exception e) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
            }
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺decDN Ϊ��
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "symmkey-16-dn",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_20(String keyLableAndTypeAndData, String encDn) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
        // ���������ŷ�
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, pinModeAndPadding, iv,
                        pinModeAndPadding, iv, "");
                if (upkiResult1.getReturnCode() != -1022) {
                    Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("ˢ��֧�����������ŷ⣺decDN Ϊ�գ�ִ�гɹ�");
            } catch (Exception e) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
            }
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺decDN ������
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "symmkey-16-dn",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_22(String keyLableAndTypeAndData, String encDn) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
        // ���������ŷ�
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, pinModeAndPadding, iv,
                        pinModeAndPadding, iv, null);
                if (upkiResult1.getReturnCode() != -1022) {
                    Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("ˢ��֧�����������ŷ⣺decDN Ϊnull��ִ�гɹ�");
            } catch (Exception e) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
            }
        }
    }

    /**
     * ˢ��֧�����������ŷ⣺decDN Ϊnull
     */
    @Test(groups = "abcjew.decryptcupfacepaywlenvelope.normal", dataProvider = "symmkey-16-dn",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptCUPFacePayWLEnvelope_21(String keyLableAndTypeAndData, String encDn) {
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
        String[][] crypto = null;
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
            crypto = (String[][]) upkiResult.getResults().get("enc_wanglian_envelope");
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
        }
        // ���������ŷ�
        if (crypto != null) {
            try {
                UpkiResult upkiResult1 = agent.decryptCUPFacePayWLEnvelope(crypto, keyLable, pinModeAndPadding, iv,
                        pinModeAndPadding, iv, null);
                if (upkiResult1.getReturnCode() != -1022) {
                    Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                System.out.println("ˢ��֧�����������ŷ⣺decDN �����ڣ�ִ�гɹ�");
            } catch (Exception e) {
                Assert.fail("ˢ��֧�����������ŷ�ʧ�ܣ�" + e.getMessage());
            }
        }
    }

}
