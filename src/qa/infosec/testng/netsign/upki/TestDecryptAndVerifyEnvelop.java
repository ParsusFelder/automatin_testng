package qa.infosec.testng.netsign.upki;

import cn.com.infosec.netsign.agent.UpkiAgent;
import cn.com.infosec.netsign.agent.UpkiResult;
import org.testng.Assert;
import org.testng.Reporter;
import org.testng.annotations.Test;
import qa.infosec.testng.netsign.dataprovider.NetSignDataProvider;
import qa.infosec.testng.netsign.dataprovider.util.ParameterUtil;
import qa.infosec.testng.netsign.dataprovider.util.ParseFile;
import qa.infosec.testng.netsign.dataprovider.util.SFTPFile;
import qa.infosec.testng.netsign.dataprovider.util.Utils;
import qa.infosec.testng.netsign.init.NetSignServerInit;

import java.util.Map;

/**
 * @author zhaoyongzhi
 * @ClassName: TestDecryptAndVerifyEnvelop
 * @date 2020-03-02 18:07
 * @Description: ���ǩ���������ŷ�
 * <p>�������ǵ㣺</p>
 * <p>1�����ǩ���������ŷ⣬ʹ������RSA֤��DN</p>
 * <p>2�����ǩ���������ŷ⣬ʹ������RSA֤��DN</p>
 * <p>3�����ǩ���������ŷ⣬ʹ�ò�������RSA֤��DN</p>
 * <p>4�����ǩ���������ŷ⣬ʹ�ù���RSA֤��DN</p>
 * <p>5�����ǩ���������ŷ⣬ʹ������SM2֤��DN</p>
 * <p>6�����ǩ���������ŷ⣬ʹ������SM2֤��DN</p>
 * <p>7�����ǩ���������ŷ⣬ʹ�ù���SM2֤��DN</p>
 * <p>8�����ǩ���������ŷ⣬ʹ������RSA֤��SN</p>
 * <p>9�����ǩ���������ŷ⣬ʹ������RSA֤��SN</p>
 * <p>10�����ǩ���������ŷ⣬ʹ�ò�������RSA֤��SN</p>
 * <p>11�����ǩ���������ŷ⣬ʹ�ù���RSA֤��SN</p>
 * <p>12�����ǩ���������ŷ⣬ʹ������SM2֤��SN</p>
 * <p>13�����ǩ���������ŷ⣬ʹ������SM2֤��SN</p>
 * <p>14�����ǩ���������ŷ⣬ʹ�ù���SM2֤��SN</p>
 * <p>15�����ǩ���������ŷ⣬ʹ������RSA֤��Bankcode</p>
 * <p>16�����ǩ���������ŷ⣬ʹ������RSA֤��Bankcode</p>
 * <p>17�����ǩ���������ŷ⣬ʹ�ò�������RSA֤��Bankcode</p>
 * <p>18�����ǩ���������ŷ⣬ʹ�ù���RSA֤��Bankcode</p>
 * <p>19�����ǩ���������ŷ⣬ʹ������SM2֤��Bankcode</p>
 * <p>20�����ǩ���������ŷ⣬ʹ������SM2֤��Bankcode</p>
 * <p>21�����ǩ���������ŷ⣬ʹ�ù���SM2֤��Bankcode</p>
 * <p>22�����ǩ���������ŷ⣬����Ϊ�ջ�null</p>
 * <p>23�����ǩ���������ŷ⣬DNΪ�ջ�null</p>
 * <p>24�����ǩ���������ŷ⣬DN��ƥ��</p>
 * <p>25�����ǩ���������ŷ⣬ժҪ�㷨Ϊ�ջ�null</p>
 * <p>26�����ǩ���������ŷ⣬ժҪ�㷨��ƥ��</p>
 * <p>27�����ǩ���������ŷ⣬���Ĵ۸�</p>
 */
@Test(groups = "abcjew.decryptandverifyenvelope")
public class TestDecryptAndVerifyEnvelop {
    static String ip, port, password;
    static String host, sftp_port, sftp_password, sftp_user;

    NetSignServerInit init = new NetSignServerInit();
    UpkiAgent agent;
    SFTPFile tmp = new SFTPFile();

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
        tmp.downFile(sftp_user, host, sftp_port, sftp_password, ParameterUtil.sftpdetailpath,
                ParameterUtil.localdetailpath);
    }

    /**
     * ���ǩ���������ŷ⣬ʹ������RSA֤��DN
     *
     * @param DN   RSA֤��DN
     * @param dAlg SHA1/SHA224/SHA256/SHA384/SHA512
     * @param sAlg SM4/AES/RC2/RC4/DES/3DES
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "normal-rsa-dn-dalg-0",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_01(String DN, String dAlg, String sAlg) {
        System.out.println("���ǩ���������ŷ⣨decryptAndVerifyEnvelop����ʹ������RSA֤��DN");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String crypto = null;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, DN, dAlg);
            if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���ǩ���������ŷ⣬ʹ������RSA֤��DN
     *
     * @param DN   RSA֤��DN
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "revoke-rsa-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_02(String DN) {
        System.out.println("���ǩ���������ŷ⣨decryptAndVerifyEnvelop����ʹ������RSA֤��DN");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String crypto = null;
        String dAlg = "SHA1";
        String sAlg = "AES";

        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }

        try {
            if ("C=CN,O=infosec,CN=C020revokedNocrlfile".equals(DN) || ("C=CN,O=infosec,OU=test3," +
                    "CN=C020revokeMatchingAnyCrlfbd").equals(DN)) {
                return;
            }
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, DN, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���ǩ���������ŷ⣬ʹ�ò�������RSA֤��DN
     *
     * @param DN   RSA֤��DN
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "nottrust-rsa-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_03(String DN) {
        System.out.println("���ǩ���������ŷ⣨decryptAndVerifyEnvelop����ʹ�ò�������RSA֤��DN");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String crypto = null;
        String dAlg = "SHA1";
        String sAlg = "AES";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, DN, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���ǩ���������ŷ⣬ʹ�ù���RSA֤��DN
     *
     * @param DN   RSA֤��DN
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "expire-rsa-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_04(String DN) {
        System.out.println("���ǩ���������ŷ⣨decryptAndVerifyEnvelop����ʹ�ù���RSA֤��DN");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String crypto = null;
        String dAlg = "SHA1";
        String sAlg = "AES";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, DN, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���ǩ���������ŷ⣬ʹ������SM2֤��DN
     *
     * @param DN   SM2֤��DN
     * @param dAlg SHA1/SHA224/SHA256/SHA384/SHA512
     * @param sAlg SM4/AES/RC2/RC4/DES/3DES
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "normal-sm2-dn-dalg-0",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_05(String DN, String dAlg, String sAlg) {
        System.out.println("���ǩ���������ŷ⣨decryptAndVerifyEnvelop����ʹ������SM2֤��DN");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String crypto = null;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, DN, dAlg);
            if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���ǩ���������ŷ⣬ʹ������SM2֤��DN
     *
     * @param DN   SM2֤��DN
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "revoke-sm2-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_06(String DN) {
        System.out.println("���ǩ���������ŷ⣨decryptAndVerifyEnvelop����ʹ������SM2֤��DN");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String crypto = null;
        String dAlg = "SHA1";
        String sAlg = "AES";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }

        try {
            if ("C=CN,O=infosec,CN=C020revokedNocrlfile".equals(DN) || ("C=CN,O=infosec,OU=test3," +
                    "CN=C020revokeMatchingAnyCrlfbd").equals(DN)) {
                return;
            }
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, DN, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���ǩ���������ŷ⣬ʹ�ù���SM2֤��DN
     *
     * @param DN   SM2֤��DN
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "expire-sm2-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_07(String DN) {
        System.out.println("���ǩ���������ŷ⣨decryptAndVerifyEnvelop����ʹ�ù���SM2֤��DN");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String crypto = null;
        String dAlg = "SHA1";
        String sAlg = "AES";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, DN, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���ǩ���������ŷ⣬ʹ������RSA֤��SN
     *
     * @param SN   RSA֤��SN
     * @param dAlg SHA1/SHA224/SHA256/SHA384/SHA512
     * @param sAlg SM4/AES/RC2/RC4/DES/3DES
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "normal-rsa-sn-dalg-0",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_08(String SN, String dAlg, String sAlg) {
        System.out.println("���ǩ���������ŷ⣨decryptAndVerifyEnvelop����ʹ������RSA֤��SN");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String crypto = null;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, SN, SN, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, SN, dAlg);
            if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���ǩ���������ŷ⣬ʹ������RSA֤��SN
     *
     * @param SN   RSA֤��SN
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "revoke-rsa-sn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_09(String SN) {
        System.out.println("���ǩ���������ŷ⣨decryptAndVerifyEnvelop����ʹ������RSA֤��SN");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String crypto = null;
        String dAlg = "SHA1";
        String sAlg = "AES";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, SN, SN, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }

        try {
            if ("0219373e13cf29".equals(SN) || "012c12835bad69".equals(SN)) {
                return;
            }
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, SN, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���ǩ���������ŷ⣬ʹ�ò�������RSA֤��SN
     *
     * @param SN   RSA֤��SN
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "nottrust-rsa-sn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_10(String SN) {
        System.out.println("���ǩ���������ŷ⣨decryptAndVerifyEnvelop����ʹ�ò�������RSA֤��SN");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String crypto = null;
        String dAlg = "SHA1";
        String sAlg = "AES";
        try {
            // ��Կ�б�����SN=50e66bcca4��֤��
            if ("50e66bcca4".equals(SN)) {
                return;
            }
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, SN, SN, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, SN, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���ǩ���������ŷ⣬ʹ�ù���RSA֤��SN
     *
     * @param SN   RSA֤��SN
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "expire-rsa-sn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_11(String SN) {
        System.out.println("���ǩ���������ŷ⣨decryptAndVerifyEnvelop����ʹ�ù���RSA֤��SN");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String crypto = null;
        String dAlg = "SHA1";
        String sAlg = "AES";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, SN, SN, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, SN, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���ǩ���������ŷ⣬ʹ������SM2֤��SN
     *
     * @param SN   SM2֤��SN
     * @param dAlg SHA1/SHA224/SHA256/SHA384/SHA512
     * @param sAlg SM4/AES/RC2/RC4/DES/3DES
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "normal-sm2-sn-dalg-0",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_12(String SN, String dAlg, String sAlg) {
        System.out.println("���ǩ���������ŷ⣨decryptAndVerifyEnvelop����ʹ������SM2֤��SN");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String crypto = null;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, SN, SN, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, SN, dAlg);
            if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���ǩ���������ŷ⣬ʹ������SM2֤��SN
     *
     * @param SN   SM2֤��SN
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "revoke-sm2-sn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_13(String SN) {
        System.out.println("���ǩ���������ŷ⣨decryptAndVerifyEnvelop����ʹ������SM2֤��SN");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String crypto = null;
        String dAlg = "SHA1";
        String sAlg = "AES";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, SN, SN, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }

        try {
            if ("C=CN,O=infosec,CN=C020revokedNocrlfile".equals(SN) || ("C=CN,O=infosec,OU=test3," +
                    "CN=C020revokeMatchingAnyCrlfbd").equals(SN)) {
                return;
            }
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, SN, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���ǩ���������ŷ⣬ʹ�ù���SM2֤��SN
     *
     * @param SN   SM2֤��SN
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "expire-sm2-sn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_14(String SN) {
        System.out.println("���ǩ���������ŷ⣨decryptAndVerifyEnvelop����ʹ�ù���SM2֤��SN");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String crypto = null;
        String dAlg = "SHA1";
        String sAlg = "AES";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, SN, SN, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, SN, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���ǩ���������ŷ⣬ʹ������RSA֤��Bankcode
     *
     * @param Bankcode RSA֤��Bankcode
     * @param dAlg     SHA1/SHA224/SHA256/SHA384/SHA512
     * @param sAlg     SM4/AES/RC2/RC4/DES/3DES
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "normal-rsa-bankcode-dalg-0",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_15(String Bankcode, String dAlg, String sAlg) {
        System.out.println("���ǩ���������ŷ⣨decryptAndVerifyEnvelop����ʹ������RSA֤��Bankcode");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        String crypto;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, Bankcode, Bankcode, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult != null && upkiResult.getReturnCode() != -100203) {
                Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage() + upkiResult.getReturnCode());
            }
            Reporter.log("����������ʽ�����ŷ�ʧ�ܣ�encryptAndSignEnvelope��������֤���޷�����bankcode��ȡ");
            return;
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, Bankcode, dAlg);
            if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���ǩ���������ŷ⣬ʹ������RSA֤��Bankcode
     *
     * @param Bankcode RSA֤��Bankcode
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "revoke-rsa-bankcode", dataProviderClass
            = NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_16(String Bankcode) {
        System.out.println("���ǩ���������ŷ⣨decryptAndVerifyEnvelop����ʹ������RSA֤��Bankcode");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        String crypto;
        String dAlg = "SHA1";
        String sAlg = "AES";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, Bankcode, Bankcode, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult != null && upkiResult.getReturnCode() != -100203) {
                Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage() + upkiResult.getReturnCode());
            }
            Reporter.log("����������ʽ�����ŷ�ʧ�ܣ�encryptAndSignEnvelope��������֤���޷�����bankcode��ȡ");
            return;
        }

        try {
            if ("C020revokeMatchingAnyCrlfbd".equals(Bankcode) || "C020revokedNocrlfile".equals(Bankcode)) {
                return;
            }
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, Bankcode, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���ǩ���������ŷ⣬ʹ�ò�������RSA֤��Bankcode
     *
     * @param Bankcode RSA֤��Bankcode
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "nottrust-rsa-bankcode",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_17(String Bankcode) {
        System.out.println("���ǩ���������ŷ⣨decryptAndVerifyEnvelop����ʹ�ò�������RSA֤��Bankcode");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        String crypto;
        String dAlg = "SHA1";
        String sAlg = "AES";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, Bankcode, Bankcode, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult != null && upkiResult.getReturnCode() != -100203) {
                Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage() + upkiResult.getReturnCode());
            }
            Reporter.log("����������ʽ�����ŷ�ʧ�ܣ�encryptAndSignEnvelope��������֤���޷�����bankcode��ȡ");
            return;
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, Bankcode, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���ǩ���������ŷ⣬ʹ�ù���RSA֤��Bankcode
     *
     * @param Bankcode RSA֤��Bankcode
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "expire-rsa-bankcode", dataProviderClass
            = NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_18(String Bankcode) {
        System.out.println("���ǩ���������ŷ⣨decryptAndVerifyEnvelop����ʹ�ù���RSA֤��Bankcode");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String crypto = null;
        String dAlg = "SHA1";
        String sAlg = "AES";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, Bankcode, Bankcode, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, Bankcode, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���ǩ���������ŷ⣬ʹ������SM2֤��Bankcode
     *
     * @param Bankcode SM2֤��Bankcode
     * @param dAlg     SHA1/SHA224/SHA256/SHA384/SHA512
     * @param sAlg     SM4/AES/RC2/RC4/DES/3DES
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "normal-sm2-bankcode-dalg-0",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_19(String Bankcode, String dAlg, String sAlg) {
        System.out.println("���ǩ���������ŷ⣨decryptAndVerifyEnvelop����ʹ������SM2֤��Bankcode");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        String crypto;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, Bankcode, Bankcode, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult != null && upkiResult.getReturnCode() != -100203) {
                Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage() + upkiResult.getReturnCode());
            }
            Reporter.log("����������ʽ�����ŷ�ʧ�ܣ�encryptAndSignEnvelope��������֤���޷�����bankcode��ȡ");
            return;
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, Bankcode, dAlg);
            if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���ǩ���������ŷ⣬ʹ������SM2֤��Bankcode
     *
     * @param Bankcode SM2֤��Bankcode
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "revoke-sm2-bankcode", dataProviderClass
            = NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_20(String Bankcode) {
        System.out.println("���ǩ���������ŷ⣨decryptAndVerifyEnvelop����ʹ������SM2֤��Bankcode");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        String crypto;
        String dAlg = "SHA1";
        String sAlg = "AES";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, Bankcode, Bankcode, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult != null && upkiResult.getReturnCode() != -100203) {
                Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage() + upkiResult.getReturnCode());
            }
            Reporter.log("����������ʽ�����ŷ�ʧ�ܣ�encryptAndSignEnvelope��������֤���޷�����bankcode��ȡ");
            return;
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, Bankcode, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���ǩ���������ŷ⣬ʹ�ù���SM2֤��Bankcode
     *
     * @param Bankcode SM2֤��Bankcode
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "expire-sm2-bankcode", dataProviderClass
            = NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_21(String Bankcode) {
        System.out.println("���ǩ���������ŷ⣨decryptAndVerifyEnvelop����ʹ�ù���SM2֤��Bankcode");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String crypto = null;
        String dAlg = "SHA1";
        String sAlg = "AES";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, Bankcode, Bankcode, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, Bankcode, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���ǩ���������ŷ⣬����Ϊ�ջ�null
     *
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_22(String crypto) {
        System.out.println("���ǩ���������ŷ⣨decryptAndVerifyEnvelop��������Ϊ�ջ�null");

        String dAlg = "SHA1";
        String DN = "CN=c020crlfbdIssueModeHTTP";

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, DN, dAlg);
            if (upkiResult1.getReturnCode() != -100212 && upkiResult1.getReturnCode() != -1011) {
                Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���ǩ���������ŷ⣬DNΪ�ջ�null
     *
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_23(String DN1) {
        System.out.println("���ǩ���������ŷ⣨decryptAndVerifyEnvelop����DNΪ�ջ�null");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String dAlg = "SHA1";
        String sAlg = "AES";
        String DN = "CN=c020crlfbdIssueModeHTTP";
        String crypto = null;
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, DN1, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���ǩ���������ŷ⣬DNΪ�ջ�null
     *
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal")
    public void testDecryptAndVerifyEnvelope_24() {
        System.out.println("���ǩ���������ŷ⣨decryptAndVerifyEnvelop����DN��ƥ��");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String dAlg = "SHA1";
        String sAlg = "AES";
        String DN = "CN=c020crlfbdIssueModeHTTP";
        String crypto = null;
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, "CN=c020crlfbdIssueModeCDP", dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���ǩ���������ŷ⣬ժҪ�㷨Ϊ�ջ�null
     *
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_25(String dAlg1) {
        System.out.println("���ǩ���������ŷ⣨decryptAndVerifyEnvelop����ժҪ�㷨Ϊ�ջ�null");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String dAlg = "SHA1";
        String sAlg = "AES";
        String DN = "CN=c020crlfbdIssueModeHTTP";
        String crypto = null;
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, DN, dAlg1);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���ǩ���������ŷ⣬ժҪ�㷨��ƥ��
     *
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal")
    public void testDecryptAndVerifyEnvelope_26() {
        System.out.println("���ǩ���������ŷ⣨decryptAndVerifyEnvelop����ժҪ�㷨��ƥ��");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String dAlg = "SHA1";
        String sAlg = "AES";
        String DN = "CN=c020crlfbdIssueModeHTTP";
        String crypto = null;
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, DN, "SHA224");
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���ǩ���������ŷ⣬���Ĵ۸�
     *
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal")
    public void testDecryptAndVerifyEnvelope_27() {
        System.out.println("���ǩ���������ŷ⣨decryptAndVerifyEnvelop�������Ĵ۸�");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String dAlg = "SHA1";
        String sAlg = "AES";
        String DN = "CN=c020crlfbdIssueModeHTTP";
        String crypto = null;
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("������ǩ���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }

        try {
            crypto = Utils.modifyData(crypto, 5, 10, "12345");
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, DN, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���ǩ���������ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }
}
