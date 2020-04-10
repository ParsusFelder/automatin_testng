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
 * @Description: 解带签名的数字信封
 * <p>用例覆盖点：</p>
 * <p>1）解带签名的数字信封，使用正常RSA证书DN</p>
 * <p>2）解带签名的数字信封，使用作废RSA证书DN</p>
 * <p>3）解带签名的数字信封，使用不受信任RSA证书DN</p>
 * <p>4）解带签名的数字信封，使用过期RSA证书DN</p>
 * <p>5）解带签名的数字信封，使用正常SM2证书DN</p>
 * <p>6）解带签名的数字信封，使用作废SM2证书DN</p>
 * <p>7）解带签名的数字信封，使用过期SM2证书DN</p>
 * <p>8）解带签名的数字信封，使用正常RSA证书SN</p>
 * <p>9）解带签名的数字信封，使用作废RSA证书SN</p>
 * <p>10）解带签名的数字信封，使用不受信任RSA证书SN</p>
 * <p>11）解带签名的数字信封，使用过期RSA证书SN</p>
 * <p>12）解带签名的数字信封，使用正常SM2证书SN</p>
 * <p>13）解带签名的数字信封，使用作废SM2证书SN</p>
 * <p>14）解带签名的数字信封，使用过期SM2证书SN</p>
 * <p>15）解带签名的数字信封，使用正常RSA证书Bankcode</p>
 * <p>16）解带签名的数字信封，使用作废RSA证书Bankcode</p>
 * <p>17）解带签名的数字信封，使用不受信任RSA证书Bankcode</p>
 * <p>18）解带签名的数字信封，使用过期RSA证书Bankcode</p>
 * <p>19）解带签名的数字信封，使用正常SM2证书Bankcode</p>
 * <p>20）解带签名的数字信封，使用作废SM2证书Bankcode</p>
 * <p>21）解带签名的数字信封，使用过期SM2证书Bankcode</p>
 * <p>22）解带签名的数字信封，密文为空或null</p>
 * <p>23）解带签名的数字信封，DN为空或null</p>
 * <p>24）解带签名的数字信封，DN不匹配</p>
 * <p>25）解带签名的数字信封，摘要算法为空或null</p>
 * <p>26）解带签名的数字信封，摘要算法不匹配</p>
 * <p>27）解带签名的数字信封，密文篡改</p>
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
     * 解带签名的数字信封，使用正常RSA证书DN
     *
     * @param DN   RSA证书DN
     * @param dAlg SHA1/SHA224/SHA256/SHA384/SHA512
     * @param sAlg SM4/AES/RC2/RC4/DES/3DES
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "normal-rsa-dn-dalg-0",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_01(String DN, String dAlg, String sAlg) {
        System.out.println("解带签名的数字信封（decryptAndVerifyEnvelop），使用正常RSA证书DN");

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
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, DN, dAlg);
            if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                Assert.fail("解带签名的数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解带签名的数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解带签名的数字信封，使用作废RSA证书DN
     *
     * @param DN   RSA证书DN
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "revoke-rsa-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_02(String DN) {
        System.out.println("解带签名的数字信封（decryptAndVerifyEnvelop），使用作废RSA证书DN");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String crypto = null;
        String dAlg = "SHA1";
        String sAlg = "AES";

        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }

        try {
            if ("C=CN,O=infosec,CN=C020revokedNocrlfile".equals(DN) || ("C=CN,O=infosec,OU=test3," +
                    "CN=C020revokeMatchingAnyCrlfbd").equals(DN)) {
                return;
            }
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, DN, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("解带签名的数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解带签名的数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解带签名的数字信封，使用不受信任RSA证书DN
     *
     * @param DN   RSA证书DN
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "nottrust-rsa-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_03(String DN) {
        System.out.println("解带签名的数字信封（decryptAndVerifyEnvelop），使用不受信任RSA证书DN");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String crypto = null;
        String dAlg = "SHA1";
        String sAlg = "AES";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, DN, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("解带签名的数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解带签名的数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解带签名的数字信封，使用过期RSA证书DN
     *
     * @param DN   RSA证书DN
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "expire-rsa-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_04(String DN) {
        System.out.println("解带签名的数字信封（decryptAndVerifyEnvelop），使用过期RSA证书DN");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String crypto = null;
        String dAlg = "SHA1";
        String sAlg = "AES";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, DN, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("解带签名的数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解带签名的数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解带签名的数字信封，使用正常SM2证书DN
     *
     * @param DN   SM2证书DN
     * @param dAlg SHA1/SHA224/SHA256/SHA384/SHA512
     * @param sAlg SM4/AES/RC2/RC4/DES/3DES
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "normal-sm2-dn-dalg-0",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_05(String DN, String dAlg, String sAlg) {
        System.out.println("解带签名的数字信封（decryptAndVerifyEnvelop），使用正常SM2证书DN");

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
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, DN, dAlg);
            if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                Assert.fail("解带签名的数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解带签名的数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解带签名的数字信封，使用作废SM2证书DN
     *
     * @param DN   SM2证书DN
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "revoke-sm2-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_06(String DN) {
        System.out.println("解带签名的数字信封（decryptAndVerifyEnvelop），使用作废SM2证书DN");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String crypto = null;
        String dAlg = "SHA1";
        String sAlg = "AES";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }

        try {
            if ("C=CN,O=infosec,CN=C020revokedNocrlfile".equals(DN) || ("C=CN,O=infosec,OU=test3," +
                    "CN=C020revokeMatchingAnyCrlfbd").equals(DN)) {
                return;
            }
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, DN, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("解带签名的数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解带签名的数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解带签名的数字信封，使用过期SM2证书DN
     *
     * @param DN   SM2证书DN
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "expire-sm2-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_07(String DN) {
        System.out.println("解带签名的数字信封（decryptAndVerifyEnvelop），使用过期SM2证书DN");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String crypto = null;
        String dAlg = "SHA1";
        String sAlg = "AES";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, DN, DN, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, DN, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("解带签名的数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解带签名的数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解带签名的数字信封，使用正常RSA证书SN
     *
     * @param SN   RSA证书SN
     * @param dAlg SHA1/SHA224/SHA256/SHA384/SHA512
     * @param sAlg SM4/AES/RC2/RC4/DES/3DES
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "normal-rsa-sn-dalg-0",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_08(String SN, String dAlg, String sAlg) {
        System.out.println("解带签名的数字信封（decryptAndVerifyEnvelop），使用正常RSA证书SN");

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
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, SN, dAlg);
            if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                Assert.fail("解带签名的数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解带签名的数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解带签名的数字信封，使用作废RSA证书SN
     *
     * @param SN   RSA证书SN
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "revoke-rsa-sn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_09(String SN) {
        System.out.println("解带签名的数字信封（decryptAndVerifyEnvelop），使用作废RSA证书SN");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String crypto = null;
        String dAlg = "SHA1";
        String sAlg = "AES";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, SN, SN, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }

        try {
            if ("0219373e13cf29".equals(SN) || "012c12835bad69".equals(SN)) {
                return;
            }
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, SN, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("解带签名的数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解带签名的数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解带签名的数字信封，使用不受信任RSA证书SN
     *
     * @param SN   RSA证书SN
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "nottrust-rsa-sn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_10(String SN) {
        System.out.println("解带签名的数字信封（decryptAndVerifyEnvelop），使用不受信任RSA证书SN");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String crypto = null;
        String dAlg = "SHA1";
        String sAlg = "AES";
        try {
            // 密钥列表中无SN=50e66bcca4的证书
            if ("50e66bcca4".equals(SN)) {
                return;
            }
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, SN, SN, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, SN, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("解带签名的数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解带签名的数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解带签名的数字信封，使用过期RSA证书SN
     *
     * @param SN   RSA证书SN
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "expire-rsa-sn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_11(String SN) {
        System.out.println("解带签名的数字信封（decryptAndVerifyEnvelop），使用过期RSA证书SN");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String crypto = null;
        String dAlg = "SHA1";
        String sAlg = "AES";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, SN, SN, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, SN, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("解带签名的数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解带签名的数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解带签名的数字信封，使用正常SM2证书SN
     *
     * @param SN   SM2证书SN
     * @param dAlg SHA1/SHA224/SHA256/SHA384/SHA512
     * @param sAlg SM4/AES/RC2/RC4/DES/3DES
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "normal-sm2-sn-dalg-0",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_12(String SN, String dAlg, String sAlg) {
        System.out.println("解带签名的数字信封（decryptAndVerifyEnvelop），使用正常SM2证书SN");

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
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, SN, dAlg);
            if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                Assert.fail("解带签名的数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解带签名的数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解带签名的数字信封，使用作废SM2证书SN
     *
     * @param SN   SM2证书SN
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "revoke-sm2-sn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_13(String SN) {
        System.out.println("解带签名的数字信封（decryptAndVerifyEnvelop），使用作废SM2证书SN");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String crypto = null;
        String dAlg = "SHA1";
        String sAlg = "AES";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, SN, SN, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }

        try {
            if ("C=CN,O=infosec,CN=C020revokedNocrlfile".equals(SN) || ("C=CN,O=infosec,OU=test3," +
                    "CN=C020revokeMatchingAnyCrlfbd").equals(SN)) {
                return;
            }
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, SN, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("解带签名的数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解带签名的数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解带签名的数字信封，使用过期SM2证书SN
     *
     * @param SN   SM2证书SN
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "expire-sm2-sn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_14(String SN) {
        System.out.println("解带签名的数字信封（decryptAndVerifyEnvelop），使用过期SM2证书SN");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String crypto = null;
        String dAlg = "SHA1";
        String sAlg = "AES";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, SN, SN, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, SN, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("解带签名的数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解带签名的数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解带签名的数字信封，使用正常RSA证书Bankcode
     *
     * @param Bankcode RSA证书Bankcode
     * @param dAlg     SHA1/SHA224/SHA256/SHA384/SHA512
     * @param sAlg     SM4/AES/RC2/RC4/DES/3DES
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "normal-rsa-bankcode-dalg-0",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_15(String Bankcode, String dAlg, String sAlg) {
        System.out.println("解带签名的数字信封（decryptAndVerifyEnvelop），使用正常RSA证书Bankcode");

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
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult != null && upkiResult.getReturnCode() != -100203) {
                Assert.fail("制作网联格式数字信封失败：" + e.getMessage() + upkiResult.getReturnCode());
            }
            Reporter.log("制作网联格式数字信封失败（encryptAndSignEnvelope）：部分证书无法根据bankcode获取");
            return;
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, Bankcode, dAlg);
            if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                Assert.fail("解带签名的数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解带签名的数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解带签名的数字信封，使用作废RSA证书Bankcode
     *
     * @param Bankcode RSA证书Bankcode
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "revoke-rsa-bankcode", dataProviderClass
            = NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_16(String Bankcode) {
        System.out.println("解带签名的数字信封（decryptAndVerifyEnvelop），使用作废RSA证书Bankcode");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        String crypto;
        String dAlg = "SHA1";
        String sAlg = "AES";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, Bankcode, Bankcode, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult != null && upkiResult.getReturnCode() != -100203) {
                Assert.fail("制作网联格式数字信封失败：" + e.getMessage() + upkiResult.getReturnCode());
            }
            Reporter.log("制作网联格式数字信封失败（encryptAndSignEnvelope）：部分证书无法根据bankcode获取");
            return;
        }

        try {
            if ("C020revokeMatchingAnyCrlfbd".equals(Bankcode) || "C020revokedNocrlfile".equals(Bankcode)) {
                return;
            }
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, Bankcode, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("解带签名的数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解带签名的数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解带签名的数字信封，使用不受信任RSA证书Bankcode
     *
     * @param Bankcode RSA证书Bankcode
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "nottrust-rsa-bankcode",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_17(String Bankcode) {
        System.out.println("解带签名的数字信封（decryptAndVerifyEnvelop），使用不受信任RSA证书Bankcode");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        String crypto;
        String dAlg = "SHA1";
        String sAlg = "AES";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, Bankcode, Bankcode, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult != null && upkiResult.getReturnCode() != -100203) {
                Assert.fail("制作网联格式数字信封失败：" + e.getMessage() + upkiResult.getReturnCode());
            }
            Reporter.log("制作网联格式数字信封失败（encryptAndSignEnvelope）：部分证书无法根据bankcode获取");
            return;
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, Bankcode, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("解带签名的数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解带签名的数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解带签名的数字信封，使用过期RSA证书Bankcode
     *
     * @param Bankcode RSA证书Bankcode
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "expire-rsa-bankcode", dataProviderClass
            = NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_18(String Bankcode) {
        System.out.println("解带签名的数字信封（decryptAndVerifyEnvelop），使用过期RSA证书Bankcode");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String crypto = null;
        String dAlg = "SHA1";
        String sAlg = "AES";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, Bankcode, Bankcode, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, Bankcode, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("解带签名的数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解带签名的数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解带签名的数字信封，使用正常SM2证书Bankcode
     *
     * @param Bankcode SM2证书Bankcode
     * @param dAlg     SHA1/SHA224/SHA256/SHA384/SHA512
     * @param sAlg     SM4/AES/RC2/RC4/DES/3DES
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "normal-sm2-bankcode-dalg-0",
            dataProviderClass = NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_19(String Bankcode, String dAlg, String sAlg) {
        System.out.println("解带签名的数字信封（decryptAndVerifyEnvelop），使用正常SM2证书Bankcode");

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
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult != null && upkiResult.getReturnCode() != -100203) {
                Assert.fail("制作网联格式数字信封失败：" + e.getMessage() + upkiResult.getReturnCode());
            }
            Reporter.log("制作网联格式数字信封失败（encryptAndSignEnvelope）：部分证书无法根据bankcode获取");
            return;
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, Bankcode, dAlg);
            if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                Assert.fail("解带签名的数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解带签名的数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解带签名的数字信封，使用作废SM2证书Bankcode
     *
     * @param Bankcode SM2证书Bankcode
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "revoke-sm2-bankcode", dataProviderClass
            = NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_20(String Bankcode) {
        System.out.println("解带签名的数字信封（decryptAndVerifyEnvelop），使用作废SM2证书Bankcode");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        String crypto;
        String dAlg = "SHA1";
        String sAlg = "AES";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, Bankcode, Bankcode, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult != null && upkiResult.getReturnCode() != -100203) {
                Assert.fail("制作网联格式数字信封失败：" + e.getMessage() + upkiResult.getReturnCode());
            }
            Reporter.log("制作网联格式数字信封失败（encryptAndSignEnvelope）：部分证书无法根据bankcode获取");
            return;
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, Bankcode, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("解带签名的数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解带签名的数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解带签名的数字信封，使用过期SM2证书Bankcode
     *
     * @param Bankcode SM2证书Bankcode
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "expire-sm2-bankcode", dataProviderClass
            = NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_21(String Bankcode) {
        System.out.println("解带签名的数字信封（decryptAndVerifyEnvelop），使用过期SM2证书Bankcode");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String crypto = null;
        String dAlg = "SHA1";
        String sAlg = "AES";
        try {
            upkiResult = agent.encryptAndSignEnvelope(pOrgData, Bankcode, Bankcode, dAlg, sAlg);
            crypto = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, Bankcode, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("解带签名的数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解带签名的数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解带签名的数字信封，密文为空或null
     *
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_22(String crypto) {
        System.out.println("解带签名的数字信封（decryptAndVerifyEnvelop），密文为空或null");

        String dAlg = "SHA1";
        String DN = "CN=c020crlfbdIssueModeHTTP";

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, DN, dAlg);
            if (upkiResult1.getReturnCode() != -100212 && upkiResult1.getReturnCode() != -1011) {
                Assert.fail("解带签名的数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解带签名的数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解带签名的数字信封，DN为空或null
     *
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_23(String DN1) {
        System.out.println("解带签名的数字信封（decryptAndVerifyEnvelop），DN为空或null");

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
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, DN1, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("解带签名的数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解带签名的数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解带签名的数字信封，DN为空或null
     *
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal")
    public void testDecryptAndVerifyEnvelope_24() {
        System.out.println("解带签名的数字信封（decryptAndVerifyEnvelop），DN不匹配");

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
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, "CN=c020crlfbdIssueModeCDP", dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("解带签名的数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解带签名的数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解带签名的数字信封，摘要算法为空或null
     *
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptAndVerifyEnvelope_25(String dAlg1) {
        System.out.println("解带签名的数字信封（decryptAndVerifyEnvelop），摘要算法为空或null");

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
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, DN, dAlg1);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("解带签名的数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解带签名的数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解带签名的数字信封，摘要算法不匹配
     *
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal")
    public void testDecryptAndVerifyEnvelope_26() {
        System.out.println("解带签名的数字信封（decryptAndVerifyEnvelop），摘要算法不匹配");

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
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }

        try {
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, DN, "SHA224");
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("解带签名的数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解带签名的数字信封失败：" + e.getMessage());
        }
    }

    /**
     * 解带签名的数字信封，密文篡改
     *
     */
    @Test(groups = "abcjew.decryptandverifyenvelope.normal")
    public void testDecryptAndVerifyEnvelope_27() {
        System.out.println("解带签名的数字信封（decryptAndVerifyEnvelop），密文篡改");

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
                Assert.fail("制作带签名的数字信封失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("制作网联格式数字信封失败：" + e.getMessage());
        }

        try {
            crypto = Utils.modifyData(crypto, 5, 10, "12345");
            UpkiResult upkiResult1 = agent.decryptAndVerifyEnvelop(crypto, DN, dAlg);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("解带签名的数字信封失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("解带签名的数字信封失败：" + e.getMessage());
        }
    }
}
