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
 * @ClassName: TestCUPNCPRawVerify
 * @date 2020-03-02 18:19
 * @Description: 核验银联无卡支付裸签名
 * <p>用例覆盖点：</p>
 * <p>1）核验银联无卡支付裸签名（CUPNCPRawVerify）：使用正常RSA证书DN验签</p>
 * <p>2）核验银联无卡支付裸签名（CUPNCPRawVerify）：使用作废RSA证书DN验签</p>
 * <p>3）核验银联无卡支付裸签名（CUPNCPRawVerify）：使用过期RSA证书DN验签</p>
 * <p>4）核验银联无卡支付裸签名（CUPNCPRawVerify）：使用正常RSA证书SN验签</p>
 * <p>5）核验银联无卡支付裸签名（CUPNCPRawVerify）：使用正常RSA证书Bankcode验签</p>
 * <p>6）核验银联无卡支付裸签名（CUPNCPRawVerify）：使用作废RSA证书Bankcode验签</p>
 * <p>7）核验银联无卡支付裸签名（CUPNCPRawVerify）：使用过期RSA证书Bankcode验签</p>
 * <p>8）核验银联无卡支付裸签名（CUPNCPRawVerify）：使用正常SM2证书DN验签</p>
 * <p>9）核验银联无卡支付裸签名（CUPNCPRawVerify）：使用作废SM2证书DN验签</p>
 * <p>10）核验银联无卡支付裸签名（CUPNCPRawVerify）：使用过期SM2证书DN验签</p>
 * <p>11）核验银联无卡支付裸签名（CUPNCPRawVerify）：使用正常SM2证书SN验签</p>
 * <p>12）核验银联无卡支付裸签名（CUPNCPRawVerify）：使用正常SM2证书Bankcode验签</p>
 * <p>13）核验银联无卡支付裸签名（CUPNCPRawVerify）：使用作废SM2证书Bankcode验签</p>
 * <p>14）核验银联无卡支付裸签名（CUPNCPRawVerify）：使用过期SM2证书Bankcode验签</p>
 * <p>15）核验银联无卡支付裸签名（CUPNCPRawVerify）：原文为null</p>
 * <p>16）核验银联无卡支付裸签名（CUPNCPRawVerify）：原文被篡改</p>
 * <p>17）核验银联无卡支付裸签名（CUPNCPRawVerify）：密文为空或null</p>
 * <p>18）核验银联无卡支付裸签名（CUPNCPRawVerify）：密文篡改</p>
 * <p>19）核验银联无卡支付裸签名（CUPNCPRawVerify）：DN为空或null</p>
 * <p>20）核验银联无卡支付裸签名（CUPNCPRawVerify）：验签DN与签名DN不一致</p>
 * <p>21）核验银联无卡支付裸签名（CUPNCPRawVerify）：摘要算法为空或null</p>
 * <p>22）核验银联无卡支付裸签名（CUPNCPRawVerify）：验签摘要算法与签名摘要算法不一致</p>
 * <p>23）核验银联无卡支付裸签名（CUPNCPRawVerify）：摘要算法错误</p>
 */
@Test(groups = "abcjew.cupncprawverify")
public class TestCUPNCPRawVerify {
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
     * 核验银联无卡支付裸签名（CUPNCPRawVerify）：使用正常RSA证书DN验签
     *
     * @param alg 摘要算法
     * @param dn  正常RSA证书DN
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "normal-rsa-dn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_01(String dn, String alg) {
        System.out.println("核验银联无卡支付裸签名（CUPNCPRawVerify）：使用正常RSA证书DN验签");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult != null) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
            }
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, dn, alg);
            bool_result = upkiResult1.getBoolResult();
            if (!bool_result || upkiResult1.getReturnCode() != 0) {
                Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult1 != null) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent() + e.getMessage());
            }
        }
    }

    /**
     * 核验银联无卡支付裸签名（CUPNCPRawVerify）：使用作废RSA证书DN验签
     *
     * @param alg 摘要算法
     * @param dn  作废RSA证书DN
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "revoke-rsa-dn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_02(String dn, String alg) {
        System.out.println("核验银联无卡支付裸签名（CUPNCPRawVerify）：使用作废RSA证书DN验签");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, dn, alg);
            bool_result = upkiResult1.getBoolResult();
            if (!"C=CN,O=infosec,OU=test3,CN=C020revokeMatchingAnyCrlfbd".equals(dn) && !("C=CN,O=infosec," +
                    "CN=C020revokedNocrlfile").equals(dn)) {
                if (bool_result || upkiResult1.getReturnCode() != -100108) {
                    Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
        }
    }

    /**
     * 核验银联无卡支付裸签名（CUPNCPRawVerify）：使用过期RSA证书DN验签
     *
     * @param alg 摘要算法
     * @param dn  过期RSA证书DN
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "expire-rsa-dn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_03(String dn, String alg) {
        System.out.println("核验银联无卡支付裸签名（CUPNCPRawVerify）：使用正常RSA证书DN验签");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, dn, alg);
            bool_result = upkiResult1.getBoolResult();
            if (bool_result || upkiResult1.getReturnCode() != -100106) {
                Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
        }
    }

    /**
     * 核验银联无卡支付裸签名（CUPNCPRawVerify）：使用正常RSA证书SN验签
     *
     * @param alg 摘要算法
     * @param sn  正常RSA证书SN
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "normal-rsa-sn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_04(String sn, String alg) {
        System.out.println("核验银联无卡支付裸签名（CUPNCPRawVerify）：使用正常RSA证书SN验签");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, sn, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, sn, alg);
            bool_result = upkiResult1.getBoolResult();
            if (!bool_result || upkiResult1.getReturnCode() != 0) {
                if (upkiResult1.getReturnCode() != -100224) {
                    Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("核验银联无卡支付裸签名（CUPNCPRawVerify）：不支持使用证书SN验签");
            }
        } catch (Exception e) {
            Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
        }
    }

    /**
     * 核验银联无卡支付裸签名（CUPNCPRawVerify）：使用正常RSA证书Bankcode验签
     *
     * @param alg      摘要算法
     * @param bankcode 正常RSA证书Bankcode
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "normal-rsa-bankcode-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_05(String bankcode, String alg) {
        System.out.println("核验银联无卡支付裸签名（CUPNCPRawVerify）：使用正常RSA证书Bankcode验签");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, bankcode, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, bankcode, alg);
            bool_result = upkiResult1.getBoolResult();
            if (!bool_result || upkiResult1.getReturnCode() != 0) {
                Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
        }
    }

    /**
     * 核验银联无卡支付裸签名（CUPNCPRawVerify）：使用作废RSA证书Bankcode验签
     *
     * @param alg      摘要算法
     * @param bankcode 作废RSA证书Bankcode
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "revoke-rsa-bankcode-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_06(String bankcode, String alg) {
        System.out.println("核验银联无卡支付裸签名（CUPNCPRawVerify）：使用作废RSA证书Bankcode验签");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, bankcode, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, bankcode, alg);
            bool_result = upkiResult1.getBoolResult();
            if (!"MatchingAnyCrlfbd".equals(bankcode) && !("C020revokeMatchingAnyCrlfbd").equals(bankcode) && !(
                    "C020revokedNocrlfile").equals(bankcode)) {
                if (bool_result || upkiResult1.getReturnCode() != -100108) {
                    Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
        }
    }

    /**
     * 核验银联无卡支付裸签名（CUPNCPRawVerify）：使用过期RSA证书Bankcode验签
     *
     * @param alg      摘要算法
     * @param bankcode 过期RSA证书Bankcode
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "expire-rsa-bankcode-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_07(String bankcode, String alg) {
        System.out.println("核验银联无卡支付裸签名（CUPNCPRawVerify）：使用正常RSA证书Bankcode验签");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, bankcode, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, bankcode, alg);
            bool_result = upkiResult1.getBoolResult();
            if (bool_result || upkiResult1.getReturnCode() != -100106) {
                Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
        }
    }

    /**
     * 核验银联无卡支付裸签名（CUPNCPRawVerify）：使用正常SM2证书DN验签
     *
     * @param alg 摘要算法
     * @param dn  正常SM2证书DN
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "normal-sm2-dn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_08(String dn, String alg) {
        System.out.println("核验银联无卡支付裸签名（CUPNCPRawVerify）：使用正常SM2证书DN验签");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, dn, alg);
            bool_result = upkiResult1.getBoolResult();
            if (!bool_result || upkiResult1.getReturnCode() != 0) {
                Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
        }
    }

    /**
     * 核验银联无卡支付裸签名（CUPNCPRawVerify）：使用作废SM2证书DN验签
     *
     * @param alg 摘要算法
     * @param dn  作废SM2证书DN
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "revoke-sm2-dn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_09(String dn, String alg) {
        System.out.println("核验银联无卡支付裸签名（CUPNCPRawVerify）：使用作废SM2证书DN验签");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, dn, alg);
            bool_result = upkiResult1.getBoolResult();
            if (bool_result || upkiResult1.getReturnCode() != -100108) {
                Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
        }
    }

    /**
     * 核验银联无卡支付裸签名（CUPNCPRawVerify）：使用过期SM2证书DN验签
     *
     * @param alg 摘要算法
     * @param dn  过期SM2证书DN
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "expire-sm2-dn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_10(String dn, String alg) {
        System.out.println("核验银联无卡支付裸签名（CUPNCPRawVerify）：使用正常SM2证书DN验签");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, dn, alg);
            bool_result = upkiResult1.getBoolResult();
            if (bool_result || upkiResult1.getReturnCode() != -100106) {
                Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
        }
    }

    /**
     * 核验银联无卡支付裸签名（CUPNCPRawVerify）：使用正常SM2证书SN验签
     *
     * @param alg 摘要算法
     * @param sn  正常SM2证书SN
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "normal-sm2-sn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_11(String sn, String alg) {
        System.out.println("核验银联无卡支付裸签名（CUPNCPRawVerify）：使用正常SM2证书SN验签");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, sn, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, sn, alg);
            bool_result = upkiResult1.getBoolResult();
            if (!bool_result || upkiResult1.getReturnCode() != 0) {
                if (upkiResult1.getReturnCode() != -100224) {
                    Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("核验银联无卡支付裸签名（CUPNCPRawVerify）：不支持使用证书SN验签");
            }
        } catch (Exception e) {
            Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
        }
    }

    /**
     * 核验银联无卡支付裸签名（CUPNCPRawVerify）：使用正常SM2证书Bankcode验签
     *
     * @param alg      摘要算法
     * @param bankcode 正常SM2证书Bankcode
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "normal-sm2-bankcode-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_12(String bankcode, String alg) {
        System.out.println("核验银联无卡支付裸签名（CUPNCPRawVerify）：使用正常SM2证书Bankcode验签");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, bankcode, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, bankcode, alg);
            bool_result = upkiResult1.getBoolResult();
            if (!bool_result || upkiResult1.getReturnCode() != 0) {
                Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
        }
    }

    /**
     * 核验银联无卡支付裸签名（CUPNCPRawVerify）：使用作废SM2证书Bankcode验签
     *
     * @param alg      摘要算法
     * @param bankcode 作废SM2证书Bankcode
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "revoke-sm2-bankcode-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_13(String bankcode, String alg) {
        System.out.println("核验银联无卡支付裸签名（CUPNCPRawVerify）：使用作废SM2证书Bankcode验签");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, bankcode, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, bankcode, alg);
            bool_result = upkiResult1.getBoolResult();
            if (bool_result || upkiResult1.getReturnCode() != -100108) {
                Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
        }
    }

    /**
     * 核验银联无卡支付裸签名（CUPNCPRawVerify）：使用过期SM2证书Bankcode验签
     *
     * @param alg      摘要算法
     * @param bankcode 过期SM2证书Bankcode
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "expire-sm2-bankcode-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_14(String bankcode, String alg) {
        System.out.println("核验银联无卡支付裸签名（CUPNCPRawVerify）：使用正常SM2证书Bankcode验签");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, bankcode, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, bankcode, alg);
            bool_result = upkiResult1.getBoolResult();
            if (bool_result || upkiResult1.getReturnCode() != -100106) {
                Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
        }
    }

    /**
     * 核验银联无卡支付裸签名（CUPNCPRawVerify）：原文为null
     */
    @Test(groups = "abcjew.cupncprawverify.normal")
    public void testCUPNCPRawVerify_15() {
        System.out.println("核验银联无卡支付裸签名（CUPNCPRawVerify）：原文为null");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        String alg = "SHA1";
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(null, sign_text, dn, alg);
            bool_result = upkiResult1.getBoolResult();
            if (bool_result || upkiResult1.getReturnCode() != -1026) {
                Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
        }
    }

    /**
     * 核验银联无卡支付裸签名（CUPNCPRawVerify）：原文被篡改
     */
    @Test(groups = "abcjew.cupncprawverify.normal")
    public void testCUPNCPRawVerify_16() {
        System.out.println("核验银联无卡支付裸签名（CUPNCPRawVerify）：原文被篡改");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        String alg = "SHA1";
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            plainText = Utils.modifyData(plainText, 5, 10, "12345");
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, dn, alg);
            bool_result = upkiResult1.getBoolResult();
            if (bool_result || upkiResult1.getReturnCode() != -100104) {
                Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
        }
    }

    /**
     * 核验银联无卡支付裸签名（CUPNCPRawVerify）：密文为空或null
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_17(String sign_text) {
        System.out.println("核验银联无卡支付裸签名（CUPNCPRawVerify）：密文为空或null");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        String alg = "SHA1";
        try {
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, dn, alg);
            bool_result = upkiResult1.getBoolResult();
            if (bool_result || upkiResult1.getReturnCode() != -1026) {
                Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult1 != null) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent() + e.getMessage());
            }
        }
    }

    /**
     * 核验银联无卡支付裸签名（CUPNCPRawVerify）：密文被篡改
     */
    @Test(groups = "abcjew.cupncprawverify.normal")
    public void testCUPNCPRawVerify_18() {
        System.out.println("核验银联无卡支付裸签名（CUPNCPRawVerify）：密文被篡改");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        String alg = "SHA1";
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult != null) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
            }
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            sign_text = Utils.modifyData(sign_text, 5, 10, "12345");
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, dn, alg);
            bool_result = upkiResult1.getBoolResult();
            if (bool_result || upkiResult1.getReturnCode() != -100104) {
                Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult1 != null) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent() + e.getMessage());
            }
        }
    }

    /**
     * 核验银联无卡支付裸签名（CUPNCPRawVerify）：DN为空或null
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_19(String dn1) {
        System.out.println("核验银联无卡支付裸签名（CUPNCPRawVerify）：使用正常RSA证书DN验签");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        String alg = "SHA1";
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult != null) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
            }
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, dn1, alg);
            bool_result = upkiResult1.getBoolResult();
            if (bool_result || upkiResult1.getReturnCode() != -100224) {
                Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult1 != null) {
                Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        }
    }

    /**
     * 核验银联无卡支付裸签名（CUPNCPRawVerify）：验签DN与签名DN不一致
     *
     */
    @Test(groups = "abcjew.cupncprawverify.normal")
    public void testCUPNCPRawVerify_20() {
        System.out.println("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签DN与签名DN不一致");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        String alg = "SHA1";
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult != null) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
            }
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, "C=cn,O=INFOSEC Technologies RSA,CN=R018信安世纪", alg);
            bool_result = upkiResult1.getBoolResult();
            if (bool_result || upkiResult1.getReturnCode() != -100104) {
                Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult1 != null) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent() + e.getMessage());
            }
        }
    }

    /**
     * 核验银联无卡支付裸签名（CUPNCPRawVerify）：摘要算法为空或null
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_21(String alg1) {
        System.out.println("核验银联无卡支付裸签名（CUPNCPRawVerify）：摘要算法为空或null");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        String alg = "SHA1";
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult != null) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
            }
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, dn, alg1);
            bool_result = upkiResult1.getBoolResult();
            if (bool_result || upkiResult1.getReturnCode() != -1026) {
                Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult1 != null) {
                Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        }
    }

    /**
     * 核验银联无卡支付裸签名（CUPNCPRawVerify）：验签摘要算法与签名摘要算法不一致
     */
    @Test(groups = "abcjew.cupncprawverify.normal")
    public void testCUPNCPRawVerify_22() {
        System.out.println("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签摘要算法与签名摘要算法不一致");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        String alg = "SHA1";
        String alg1 = "SHA224";
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult != null) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
            }
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, dn, alg1);
            bool_result = upkiResult1.getBoolResult();
            if (bool_result || upkiResult1.getReturnCode() != -100104) {
                Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult1 != null) {
                Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        }
    }

    /**
     * 核验银联无卡支付裸签名（CUPNCPRawVerify）：摘要算法错误
     */
    @Test(groups = "abcjew.cupncprawverify.normal")
    public void testCUPNCPRawVerify_23() {
        System.out.println("核验银联无卡支付裸签名（CUPNCPRawVerify）：摘要算法错误");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        String alg = "SHA1";
        String alg1 = "SHA3";
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult != null) {
                Assert.fail("编制银联无卡支付裸签名（CUPNCPRawSign）：签名失败" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
            }
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, dn, alg1);
            bool_result = upkiResult1.getBoolResult();
            if (bool_result || upkiResult1.getReturnCode() != -100112) {
                Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult1 != null) {
                Assert.fail("核验银联无卡支付裸签名（CUPNCPRawVerify）：验签名失败" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        }
    }
}
