package qa.infosec.testng.netsign.upki;

import cn.com.infosec.netsign.agent.UpkiAgent;
import cn.com.infosec.netsign.agent.UpkiResult;
import cn.com.infosec.util.Base64;
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
 * @ClassName: TestDeatachedVerifyHash
 * @date 2020-03-02 18:15
 * @Description: Detached验摘要
 * <p>用例覆盖点：</p>
 * <p>1）Detached验摘要（detachedVerifyHash）:使用正常RSA证书DN验签</p>
 * <p>2）Detached验摘要（detachedVerifyHash）:使用作废RSA证书DN验签</p>
 * <p>3）Detached验摘要（detachedVerifyHash）:使用不受信任RSA证书DN验签</p>
 * <p>4）Detached验摘要（detachedVerifyHash）:使用过期RSA证书DN验签</p>
 * <p>5）Detached验摘要（detachedVerifyHash）:使用正常RSA证书SN验签</p>
 * <p>6）Detached验摘要（detachedVerifyHash）:使用作废RSA证书SN验签</p>
 * <p>7）Detached验摘要（detachedVerifyHash）:使用不受信任RSA证书SN验签</p>
 * <p>8）Detached验摘要（detachedVerifyHash）:使用过期RSA证书SN验签</p>
 * <p>9）Detached验摘要（detachedVerifyHash）:使用正常RSA证书Bankcode验签</p>
 * <p>10）Detached验摘要（detachedVerifyHash）:使用作废RSA证书Bankcode验签</p>
 * <p>11）Detached验摘要（detachedVerifyHash）:使用不受信任RSA证书Bankcode验签</p>
 * <p>12）Detached验摘要（detachedVerifyHash）:使用过期RSA证书Bankcode验签</p>
 * <p>13）Detached验摘要（detachedVerifyHash）:使用正常SM2证书DN验签</p>
 * <p>14）Detached验摘要（detachedVerifyHash）:使用作废SM2证书DN验签</p>
 * <p>15）Detached验摘要（detachedVerifyHash）:使用过期SM2证书DN验签</p>
 * <p>16）Detached验摘要（detachedVerifyHash）:使用正常SM2证书SN验签</p>
 * <p>17）Detached验摘要（detachedVerifyHash）:使用作废SM2证书SN验签</p>
 * <p>18）Detached验摘要（detachedVerifyHash）:使用过期SM2证书SN验签</p>
 * <p>19）Detached验摘要（detachedVerifyHash）:使用正常SM2证书Bankcode验签</p>
 * <p>20）Detached验摘要（detachedVerifyHash）:使用作废SM2证书Bankcode验签</p>
 * <p>21）Detached验摘要（detachedVerifyHash）:使用过期SM2证书Bankcode验签</p>
 * <p>22）Detached验摘要（detachedVerifyHash）:原文为空或null</p>
 * <p>23）Detached验摘要（detachedVerifyHash）:密文为空或null</p>
 * <p>24）Detached验摘要（detachedVerifyHash）:密文篡改</p>
 */
public class TestDeatachedVerifyHash {
    static String ip, port, password;
    static String host, sftp_port, sftp_password, sftp_user;

    NetSignServerInit init = new NetSignServerInit();
    UpkiAgent agent;
    SFTPFile tmp = new SFTPFile();

    {
        // 解析netsignconfig.properties配置文件，获取所需信息,confpath=null 使用默认路径
        Map<String, String> map = ParseFile.parseProperties(null);
        ip = map.get("ServerIP");
        port = map.get("ServerPortPBC2G");
        password = map.get("APIPassword");
        host = map.get("sftp_ip");
        sftp_port = map.get("sftp_port");
        sftp_user = map.get("sftp_user");
        sftp_password = map.get("sftp_password");

        agent = init.upkiStart(ip, port, password, true, 20);
        tmp.downFile(sftp_user, host, sftp_port, sftp_password, ParameterUtil.sftpkeystorepath,
                ParameterUtil.keystorepath);
        System.out.println("NetSignServerInit OK");
    }

    /**
     * Detached验摘要（detachedVerifyHash）:使用正常RSA证书DN验签
     *
     * @param dn  证书DN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "normal-rsa-dn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_01(String dn, String alg) {
        System.out.println("Detached验摘要（detachedVerifyHash）:使用正常RSA证书DN验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Detached签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                Assert.fail("Detached验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached验摘要（detachedVerifyHash）:使用作废RSA证书DN验签
     *
     * @param dn  证书DN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "revoke-rsa-dn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_02(String dn, String alg) {
        System.out.println("Detached验摘要（detachedVerifyHash）:使用作废RSA证书DN验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;

        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Detached签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage() + upkiResult.getReturnCode());
        }

        try {

            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1.getReturnCode() != -100108) {
                if (!"C=CN,O=infosec,OU=test3,CN=C020revokeMatchingAnyCrlfbd".equals(dn) && !("C=CN,O=infosec," +
                        "CN=C020revokedNocrlfile").equals(dn)) {
                    Assert.fail("Detached验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail("Detached验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached验摘要（detachedVerifyHash）:使用不受信任RSA证书DN验签
     *
     * @param dn  证书DN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "nottrust-rsa-dn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_03(String dn, String alg) {
        System.out.println("Detached验摘要（detachedVerifyHash）:使用不受信任RSA证书DN验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Detached签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            UpkiResult upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1.getReturnCode() != -100124) {
                Assert.fail("Detached验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage());
        }
    }

    /**
     * Detached验摘要（detachedVerifyHash）:使用过期RSA证书DN验签
     *
     * @param dn  证书DN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "expire-rsa-dn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_04(String dn, String alg) {
        System.out.println("Detached验摘要（detachedVerifyHash）:使用过期RSA证书DN验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Detached签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != -100106) {
                Assert.fail("Detached验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached验摘要（detachedVerifyHash）:使用正常RSA证书SN验签
     *
     * @param sn  证书SN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "normal-rsa-sn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_05(String sn, String alg) {
        System.out.println("Detached验摘要（detachedVerifyHash）:使用正常RSA证书SN验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, sn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Detached签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != 0) {
                Assert.fail("Detached验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached验摘要（detachedVerifyHash）:使用作废RSA证书SN验签
     *
     * @param sn  证书SN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "revoke-rsa-sn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_06(String sn, String alg) {
        System.out.println("Detached验摘要（detachedVerifyHash）:使用作废RSA证书SN验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;

        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, sn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Detached签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage() + upkiResult.getReturnCode());
        }

        try {

            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1.getReturnCode() != -100108) {
                if (!"0219373e13cf29".equals(sn) && !("012c12835bad69").equals(sn)) {
                    Assert.fail("Detached验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail("Detached验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached验摘要（detachedVerifyHash）:使用不受信任RSA证书SN验签
     *
     * @param sn  证书SN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "nottrust-rsa-sn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_07(String sn, String alg) {
        System.out.println("Detached验摘要（detachedVerifyHash）:使用不受信任RSA证书SN验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        String digestData = null;
        String pSignData;
        try {
            if (sn.equals("50e66bcca4")) {
                return;
            }
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, sn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Detached签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            UpkiResult upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1.getReturnCode() != -100124) {
                if (!"50e66bcca4".equals(sn)) {
                    Assert.fail("Detached验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage());
        }
    }

    /**
     * Detached验摘要（detachedVerifyHash）:使用过期RSA证书SN验签
     *
     * @param sn  证书SN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "expire-rsa-sn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_08(String sn, String alg) {
        System.out.println("Detached验摘要（detachedVerifyHash）:使用过期RSA证书SN验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, sn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Detached签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != -100106) {
                Assert.fail("Detached验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached验摘要（detachedVerifyHash）:使用正常RSA证书Bankcode验签
     *
     * @param bankcode 证书Bankcode
     * @param alg      摘要算法
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "normal-rsa-bankcode-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_09(String bankcode, String alg) {
        System.out.println("Detached验摘要（detachedVerifyHash）:使用正常RSA证书Bankcode验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, bankcode, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Detached签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != 0) {
                Assert.fail("Detached验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached验摘要（detachedVerifyHash）:使用作废RSA证书Bankcode验签
     *
     * @param bankcode 证书Bankcode
     * @param alg      摘要算法
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "revoke-rsa-bankcode-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_10(String bankcode, String alg) {
        System.out.println("Detached验摘要（detachedVerifyHash）:使用作废RSA证书Bankcode验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;

        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, bankcode, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Detached签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage() + upkiResult.getReturnCode());
        }

        try {

            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1.getReturnCode() != -100108) {
                if (!"MatchingAnyCrlfbd".equals(bankcode) && !("C020revokeMatchingAnyCrlfbd").equals(bankcode) && !(
                        "C020revokedNocrlfile").equals(bankcode)) {
                    Assert.fail("Detached验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail("Detached验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached验摘要（detachedVerifyHash）:使用不受信任RSA证书Bankcode验签
     *
     * @param bankcode 证书Bankcode
     * @param alg      摘要算法
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "nottrust-rsa-bankcode-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_11(String bankcode, String alg) {
        System.out.println("Detached验摘要（detachedVerifyHash）:使用不受信任RSA证书Bankcode验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, bankcode, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Detached签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            UpkiResult upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1.getReturnCode() != -100124) {
                Assert.fail("Detached验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage());
        }
    }

    /**
     * Detached验摘要（detachedVerifyHash）:使用过期RSA证书Bankcode验签
     *
     * @param bankcode 证书Bankcode
     * @param alg      摘要算法
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "expire-rsa-bankcode-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_12(String bankcode, String alg) {
        System.out.println("Detached验摘要（detachedVerifyHash）:使用过期RSA证书Bankcode验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, bankcode, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Detached签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != -100106) {
                Assert.fail("Detached验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached验摘要（detachedVerifyHash）:使用正常SM2证书DN验签
     *
     * @param dn  证书DN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "normal-sm2-dn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_13(String dn, String alg) {
        System.out.println("Detached验摘要（detachedVerifyHash）:使用正常SM2证书DN验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                if (upkiResult.getReturnCode() != -100004 && !"SHA1".equals(alg)) {
                    Assert.fail("Detached签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                return;
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                if (upkiResult1.getReturnCode() != -100129) {
                    Assert.fail("Detached验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("Detached验摘要（DetachedVerifyHash）：国密证书验签时不支持SHA256算法");
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached验摘要（detachedVerifyHash）:使用作废SM2证书DN验签
     *
     * @param dn  证书DN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "revoke-sm2-dn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_14(String dn, String alg) {
        System.out.println("Detached验摘要（detachedVerifyHash）:使用作废SM2证书DN验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;

        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                if (upkiResult.getReturnCode() != -100004 && !"SHA1".equals(alg)) {
                    Assert.fail("Detached签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                return;
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage() + upkiResult.getReturnCode());
        }

        try {

            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1.getReturnCode() != -100108) {
                Assert.fail("Detached验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached验摘要（detachedVerifyHash）:使用过期SM2证书DN验签
     *
     * @param dn  证书DN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "expire-sm2-dn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_15(String dn, String alg) {
        System.out.println("Detached验摘要（detachedVerifyHash）:使用过期SM2证书DN验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                if (upkiResult.getReturnCode() != -100004 && !"SHA1".equals(alg)) {
                    Assert.fail("Detached签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                return;
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != -100106) {
                Assert.fail("Detached验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached验摘要（detachedVerifyHash）:使用正常SM2证书SN验签
     *
     * @param sn  证书SN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "normal-sm2-sn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_16(String sn, String alg) {
        System.out.println("Detached验摘要（detachedVerifyHash）:使用正常SM2证书SN验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, sn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                if (upkiResult.getReturnCode() != -100004 && !"SHA1".equals(alg)) {
                    Assert.fail("Detached签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                return;
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != 0) {
                if (upkiResult1.getReturnCode() != -100129) {
                    Assert.fail("Detached验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("Detached验摘要（DetachedVerifyHash）：国密证书验签时不支持SHA256算法");
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached验摘要（detachedVerifyHash）:使用作废SM2证书SN验签
     *
     * @param sn  证书SN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "revoke-sm2-sn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_17(String sn, String alg) {
        System.out.println("Detached验摘要（detachedVerifyHash）:使用作废SM2证书SN验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;

        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, sn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                if (upkiResult.getReturnCode() != -100004 && !"SHA1".equals(alg)) {
                    Assert.fail("Detached签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                return;
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage() + upkiResult.getReturnCode());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1.getReturnCode() != -100108) {
                Assert.fail("Detached验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached验摘要（detachedVerifyHash）:使用过期SM2证书SN验签
     *
     * @param sn  证书SN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "expire-sm2-sn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_18(String sn, String alg) {
        System.out.println("Detached验摘要（detachedVerifyHash）:使用过期SM2证书SN验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, sn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                if (upkiResult.getReturnCode() != -100004 && !"SHA1".equals(alg)) {
                    Assert.fail("Detached签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                return;
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != -100106) {
                Assert.fail("Detached验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (
                Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }

    }

    /**
     * Detached验摘要（detachedVerifyHash）:使用正常SM2证书Bankcode验签
     *
     * @param bankcode 证书Bankcode
     * @param alg      摘要算法
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "normal-sm2-bankcode-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_19(String bankcode, String alg) {
        System.out.println("Detached验摘要（detachedVerifyHash）:使用正常SM2证书Bankcode验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, bankcode, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                if (upkiResult.getReturnCode() != -100004 && !"SHA1".equals(alg)) {
                    Assert.fail("Detached签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                return;
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != 0) {
                if (upkiResult1.getReturnCode() != -100129) {
                    Assert.fail("Detached验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("Detached验摘要（DetachedVerifyHash）：国密证书验签时不支持SHA256算法");
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached验摘要（detachedVerifyHash）:使用作废SM2证书Bankcode验签
     *
     * @param bankcode 证书Bankcode
     * @param alg      摘要算法
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "revoke-sm2-bankcode-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_20(String bankcode, String alg) {
        System.out.println("Detached验摘要（detachedVerifyHash）:使用作废SM2证书Bankcode验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;

        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, bankcode, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                if (upkiResult.getReturnCode() != -100004 && !"SHA1".equals(alg)) {
                    Assert.fail("Detached签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                return;
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage() + upkiResult.getReturnCode());
        }

        try {

            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1.getReturnCode() != -100108) {
                if (upkiResult1.getReturnCode() != -100130 && "SHA1".equals(alg)) {
                    Assert.fail("Detached验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("Detached验摘要（DetachedVerifyHash）：国密证书验签时不支持SHA1算法");
            }
        } catch (Exception e) {
            Assert.fail("Detached验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached验摘要（detachedVerifyHash）:使用过期SM2证书Bankcode验签
     *
     * @param bankcode 证书Bankcode
     * @param alg      摘要算法
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "expire-sm2-bankcode-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_21(String bankcode, String alg) {
        System.out.println("Detached验摘要（detachedVerifyHash）:使用过期SM2证书Bankcode验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, bankcode, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                if (upkiResult.getReturnCode() != -100004 && !"SHA1".equals(alg)) {
                    Assert.fail("Detached签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                return;
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != -100106) {
                Assert.fail("Detached验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached验摘要（detachedVerifyHash）:原文为空或null
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_22(String str) {
        System.out.println("Detached验摘要（detachedVerifyHash）:原文为空或null");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        String alg = "SHA1";
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Detached签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.detachedVerifyHash(str, pSignData);
            if (upkiResult1.getReturnCode() != -1011 && upkiResult1.getReturnCode() != -100101) {
                Assert.fail("Detached验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Detached验摘要（detachedVerifyHash）:密文为空或null
     */
    @Test(groups = "abcjew.detachedverifyhash.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedVerifyHash_23(String pSignData) {
        System.out.println("Detached验摘要（detachedVerifyHash）:密文为空或null");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        String alg = "SHA1";
        UpkiResult upkiResult1 = null;
        String digestData = null;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1.getReturnCode() != -1011 && upkiResult1.getReturnCode() != -100004) {
                Assert.fail("Detached验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }


    /**
     * Detached验摘要（detachedVerifyHash）:密文篡改
     */
    @Test(groups = "abcjew.detachedverifyhash.normal")
    public void testDetachedVerifyHash_24() {
        System.out.println("Detached验摘要（detachedVerifyHash）:密文篡改");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        String alg = "SHA1";
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Detached签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            pSignData = Utils.modifyData(pSignData, 5, 10, "abcde");
            upkiResult1 = agent.detachedVerifyHash(digestData, pSignData);
            if (upkiResult1.getReturnCode() != -1011) {
                Assert.fail("Detached验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Detached验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }
}
