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
 * @ClassName: TestRawVerifyHash
 * @date 2020-03-20 18:09
 * @Description: RAW验摘要
 * <p>用例覆盖点：</p>
 * <p>1）Raw验摘要（rawVerifyHash）:使用正常RSA证书DN验签</p>
 * <p>2）Raw验摘要（rawVerifyHash）:使用作废RSA证书DN验签</p>
 * <p>3）Raw验摘要（rawVerifyHash）:使用不受信任RSA证书DN验签</p>
 * <p>4）Raw验摘要（rawVerifyHash）:使用过期RSA证书DN验签</p>
 * <p>5）Raw验摘要（rawVerifyHash）:使用正常RSA证书SN验签</p>
 * <p>6）Raw验摘要（rawVerifyHash）:使用作废RSA证书SN验签</p>
 * <p>7）Raw验摘要（rawVerifyHash）:使用不受信任RSA证书SN验签</p>
 * <p>8）Raw验摘要（rawVerifyHash）:使用过期RSA证书SN验签</p>
 * <p>9）Raw验摘要（rawVerifyHash）:使用正常RSA证书Bankcode验签</p>
 * <p>10）Raw验摘要（rawVerifyHash）:使用作废RSA证书Bankcode验签</p>
 * <p>11）Raw验摘要（rawVerifyHash）:使用不受信任RSA证书Bankcode验签</p>
 * <p>12）Raw验摘要（rawVerifyHash）:使用过期RSA证书Bankcode验签</p>
 * <p>13）Raw验摘要（rawVerifyHash）:使用正常SM2证书DN验签</p>
 * <p>14）Raw验摘要（rawVerifyHash）:使用作废SM2证书DN验签</p>
 * <p>15）Raw验摘要（rawVerifyHash）:使用过期SM2证书DN验签</p>
 * <p>16）Raw验摘要（rawVerifyHash）:使用正常SM2证书SN验签</p>
 * <p>17）Raw验摘要（rawVerifyHash）:使用作废SM2证书SN验签</p>
 * <p>18）Raw验摘要（rawVerifyHash）:使用过期SM2证书SN验签</p>
 * <p>19）Raw验摘要（rawVerifyHash）:使用正常SM2证书Bankcode验签</p>
 * <p>20）Raw验摘要（rawVerifyHash）:使用作废SM2证书Bankcode验签</p>
 * <p>21）Raw验摘要（rawVerifyHash）:使用过期SM2证书Bankcode验签</p>
 * <p>22）Raw验摘要（rawVerifyHash）:使用正常RSA证书DN签名，公钥验签</p>
 * <p>23）Raw验摘要（rawVerifyHash）:使用作废RSA证书DN签名，公钥验签</p>
 * <p>24）Raw验摘要（rawVerifyHash）:使用过期RSA证书DN签名，公钥验签</p>
 * <p>25）Raw验摘要（rawVerifyHash）:使用不受信任RSA证书DN签名，公钥验签</p>
 * <p>26）Raw验摘要（rawVerifyHash）:使用正常RSA证书SN签名，公钥验签</p>
 * <p>27）Raw验摘要（rawVerifyHash）:使用作废RSA证书SN签名，公钥验签</p>
 * <p>28）Raw验摘要（rawVerifyHash）:使用过期RSA证书SN签名，公钥验签</p>
 * <p>29）Raw验摘要（rawVerifyHash）:使用不受信任RSA证书SN签名，公钥验签</p>
 * <p>30）Raw验摘要（rawVerifyHash）:使用正常SM2证书DN签名，公钥验签</p>
 * <p>31）Raw验摘要（rawVerifyHash）:使用作废SM2证书DN签名，公钥验签</p>
 * <p>32）Raw验摘要（rawVerifyHash）:使用过期SM2证书DN签名，公钥验签</p>
 * <p>33）Raw验摘要（rawVerifyHash）:使用正常SM2证书SN签名，公钥验签</p>
 * <p>34）Raw验摘要（rawVerifyHash）:使用作废SM2证书SN签名，公钥验签</p>
 * <p>35）Raw验摘要（rawVerifyHash）:使用过期SM2证书SN签名，公钥验签</p>
 * <p>36）Raw验摘要（rawVerifyHash）:原文为空或null</p>
 * <p>37）Raw验摘要（rawVerifyHash）:密文为空或null</p>
 * <p>38）Raw验摘要（rawVerifyHash）:摘要算法为空或null</p>
 * <p>39）Raw验摘要（rawVerifyHash）:DN和Base64公钥同时为空或null</p>
 * <p>40）Raw验摘要（rawVerifyHash）:验签DN与签名使用DN不匹配</p>
 * <p>41）Raw验摘要（rawVerifyHash）:摘要算法内容错误</p>
 * <p>42）Raw验摘要（rawVerifyHash）:密文篡改</p>
 */
@Test(groups = "abcjew.rawverifyhash")
public class TestRawVerifyHash {
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
     * Raw验摘要（rawVerifyHash）:使用正常RSA证书DN验签
     *
     * @param dn  证书DN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "normal-rsa-dn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_01(String dn, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用正常RSA证书DN验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, dn, alg, pSignData, null);
            if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:使用作废RSA证书DN验签
     *
     * @param dn  证书DN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "revoke-rsa-dn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_02(String dn, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用作废RSA证书DN验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;

        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage() + upkiResult.getReturnCode());
        }

        try {

            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, dn, alg, pSignData, null);
            if (upkiResult1.getReturnCode() != -100108) {
                if (!"C=CN,O=infosec,OU=test3,CN=C020revokeMatchingAnyCrlfbd".equals(dn) && !("C=CN,O=infosec," +
                        "CN=C020revokedNocrlfile").equals(dn)) {
                    Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail("Raw验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:使用不受信任RSA证书DN验签
     *
     * @param dn  证书DN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "nottrust-rsa-dn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_03(String dn, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用不受信任RSA证书DN验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            UpkiResult upkiResult1 = agent.rawVerifyHash(digestData, dn, alg, pSignData, null);
            if (upkiResult1.getReturnCode() != -100124) {
                Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:使用过期RSA证书DN验签
     *
     * @param dn  证书DN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "expire-rsa-dn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_04(String dn, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用过期RSA证书DN验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, dn, alg, pSignData, null);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != -100106) {
                Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:使用正常RSA证书SN验签
     *
     * @param sn  证书SN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "normal-rsa-sn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_05(String sn, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用正常RSA证书SN验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, sn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, sn, alg, pSignData, null);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != 0) {
                Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:使用作废RSA证书SN验签
     *
     * @param sn  证书SN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "revoke-rsa-sn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_06(String sn, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用作废RSA证书SN验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;

        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, sn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage() + upkiResult.getReturnCode());
        }

        try {

            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, sn, alg, pSignData, null);
            if (upkiResult1.getReturnCode() != -100108) {
                if (!"0219373e13cf29".equals(sn) && !("012c12835bad69").equals(sn)) {
                    Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail("Raw验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:使用不受信任RSA证书SN验签
     *
     * @param sn  证书SN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "nottrust-rsa-sn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_07(String sn, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用不受信任RSA证书SN验签");

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
            upkiResult = agent.rawSignHash(digestData, sn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            UpkiResult upkiResult1 = agent.rawVerifyHash(digestData, sn, alg, pSignData, null);
            if (upkiResult1.getReturnCode() != -100124) {
                if (!"50e66bcca4".equals(sn)) {
                    Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:使用过期RSA证书SN验签
     *
     * @param sn  证书SN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "expire-rsa-sn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_08(String sn, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用过期RSA证书SN验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, sn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, sn, alg, pSignData, null);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != -100106) {
                Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:使用正常RSA证书Bankcode验签
     *
     * @param bankcode 证书Bankcode
     * @param alg      摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "normal-rsa-bankcode-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_09(String bankcode, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用正常RSA证书Bankcode验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, bankcode, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, bankcode, alg, pSignData, null);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != 0) {
                Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:使用作废RSA证书Bankcode验签
     *
     * @param bankcode 证书Bankcode
     * @param alg      摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "revoke-rsa-bankcode-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_10(String bankcode, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用作废RSA证书Bankcode验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;

        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, bankcode, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage() + upkiResult.getReturnCode());
        }

        try {

            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, bankcode, alg, pSignData, null);
            if (upkiResult1.getReturnCode() != -100108) {
                if (!"MatchingAnyCrlfbd".equals(bankcode) && !("C020revokeMatchingAnyCrlfbd").equals(bankcode) && !(
                        "C020revokedNocrlfile").equals(bankcode)) {
                    Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail("Raw验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:使用不受信任RSA证书Bankcode验签
     *
     * @param bankcode 证书Bankcode
     * @param alg      摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "nottrust-rsa-bankcode-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_11(String bankcode, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用不受信任RSA证书Bankcode验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, bankcode, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            UpkiResult upkiResult1 = agent.rawVerifyHash(digestData, bankcode, alg, pSignData, null);
            if (upkiResult1.getReturnCode() != -100124) {
                Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:使用过期RSA证书Bankcode验签
     *
     * @param bankcode 证书Bankcode
     * @param alg      摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "expire-rsa-bankcode-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_12(String bankcode, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用过期RSA证书Bankcode验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, bankcode, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, bankcode, alg, pSignData, null);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != -100106) {
                Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:使用正常SM2证书DN验签
     *
     * @param dn  证书DN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "normal-sm2-dn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_13(String dn, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用正常SM2证书DN验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, dn, alg, pSignData, null);
            if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                if (upkiResult1.getReturnCode() != -100130 || !"SHA1".equals(alg)) {
                    Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("Raw验摘要（RawVerifyHash）：国密证书验签时不支持SHA1算法");
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:使用作废SM2证书DN验签
     *
     * @param dn  证书DN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "revoke-sm2-dn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_14(String dn, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用作废SM2证书DN验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;

        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage() + upkiResult.getReturnCode());
        }

        try {

            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, dn, alg, pSignData, null);
            if (upkiResult1.getReturnCode() != -100108) {
                if (upkiResult1.getReturnCode() != -100130 || !"SHA1".equals(alg)) {
                    Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("Raw验摘要（RawVerifyHash）：国密证书验签时不支持SHA1算法");
            }
        } catch (Exception e) {
            Assert.fail("Raw验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:使用过期SM2证书DN验签
     *
     * @param dn  证书DN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "expire-sm2-dn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_15(String dn, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用过期SM2证书DN验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, dn, alg, pSignData, null);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != -100106) {
                if (upkiResult1.getReturnCode() != -100130 || !"SHA1".equals(alg)) {
                    Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("Raw验摘要（RawVerifyHash）：国密证书验签时不支持SHA1算法");
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:使用正常SM2证书SN验签
     *
     * @param sn  证书SN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "normal-sm2-sn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_16(String sn, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用正常SM2证书SN验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, sn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, sn, alg, pSignData, null);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != 0) {
                if (upkiResult1.getReturnCode() != -100130 && "SHA1".equals(alg)) {
                    Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("Raw验摘要（RawVerifyHash）：国密证书验签时不支持SHA1算法");
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:使用作废SM2证书SN验签
     *
     * @param sn  证书SN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "revoke-sm2-sn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_17(String sn, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用作废SM2证书SN验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;

        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, sn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage() + upkiResult.getReturnCode());
        }

        try {

            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, sn, alg, pSignData, null);
            if (upkiResult1.getReturnCode() != -100108) {
                if (upkiResult1.getReturnCode() != -100130 && "SHA1".equals(alg)) {
                    Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("Raw验摘要（RawVerifyHash）：国密证书验签时不支持SHA1算法");
            }
        } catch (Exception e) {
            Assert.fail("Raw验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:使用过期SM2证书SN验签
     *
     * @param sn  证书SN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "expire-sm2-sn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_18(String sn, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用过期SM2证书SN验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, sn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, sn, alg, pSignData, null);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != -100106) {
                if (upkiResult1.getReturnCode() != -100130 && "SHA1".equals(alg)) {
                    Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("Raw验摘要（RawVerifyHash）：国密证书验签时不支持SHA1算法");
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:使用正常SM2证书Bankcode验签
     *
     * @param bankcode 证书Bankcode
     * @param alg      摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "normal-sm2-bankcode-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_19(String bankcode, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用正常SM2证书Bankcode验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, bankcode, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, bankcode, alg, pSignData, null);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != 0) {
                if (upkiResult1.getReturnCode() != -100130 && "SHA1".equals(alg)) {
                    Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("Raw验摘要（RawVerifyHash）：国密证书验签时不支持SHA1算法");
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:使用作废SM2证书Bankcode验签
     *
     * @param bankcode 证书Bankcode
     * @param alg      摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "revoke-sm2-bankcode-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_20(String bankcode, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用作废SM2证书Bankcode验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;

        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, bankcode, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage() + upkiResult.getReturnCode());
        }

        try {

            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, bankcode, alg, pSignData, null);
            if (upkiResult1.getReturnCode() != -100108) {
                if (upkiResult1.getReturnCode() != -100130 && "SHA1".equals(alg)) {
                    Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("Raw验摘要（RawVerifyHash）：国密证书验签时不支持SHA1算法");
            }
        } catch (Exception e) {
            Assert.fail("Raw验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:使用过期SM2证书Bankcode验签
     *
     * @param bankcode 证书Bankcode
     * @param alg      摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "expire-sm2-bankcode-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_21(String bankcode, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用过期SM2证书Bankcode验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, bankcode, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, bankcode, alg, pSignData, null);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != -100106) {
                if (upkiResult1.getReturnCode() != -100130 && "SHA1".equals(alg)) {
                    Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("Raw验摘要（RawVerifyHash）：国密证书验签时不支持SHA1算法");
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:使用正常RSA证书DN签名，公钥验签
     *
     * @param dn  证书DN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "normal-rsa-dn-base64-salg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_22(String str, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用正常RSA证书DN签名，公钥验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String[] split = str.split("%");
        String dn = split[0];
        String sPublickey = split[1];
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, null, alg, pSignData, sPublickey);
            if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:使用作废RSA证书DN签名，公钥验签
     *
     * @param dn  证书DN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "revoke-rsa-dn-base64-salg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_23(String str, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用作废RSA证书DN签名，公钥验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String[] split = str.split("%");
        String dn = split[0];
        String sPublickey = split[1];
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, null, alg, pSignData, sPublickey);
            if (upkiResult1.getReturnCode() != -100108) {
                if (!"C=CN,O=infosec,OU=test3,CN=C020revokeMatchingAnyCrlfbd".equals(dn) && !("C=CN,O=infosec," +
                        "CN=C020revokedNocrlfile").equals(dn)) {
                    Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail("Raw验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:使用过期RSA证书DN签名，公钥验签
     *
     * @param dn  证书DN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "expire-rsa-dn-base64-salg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_24(String str, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用过期RSA证书DN签名，公钥验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String[] split = str.split("%");
        String dn = split[0];
        String sPublickey = split[1];
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, null, alg, pSignData, sPublickey);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != -100106) {
                Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:使用不受信任RSA证书DN签名，公钥验签
     *
     * @param dn  证书DN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "nottrust-rsa-dn-base64-salg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_25(String str, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用不受信任RSA证书DN签名，公钥验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String[] split = str.split("%");
        String dn = split[0];
        String sPublickey = split[1];
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, null, alg, pSignData, sPublickey);
            if (upkiResult1.getReturnCode() != -100124) {
                if (upkiResult1.getReturnCode() != -100106) {
                    Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("=========数据源数据使用的不受信任证书已经过期，需要换新的了=========");
            }
        } catch (Exception e) {
            Assert.fail("Raw验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:使用正常RSA证书SN签名，公钥验签
     *
     * @param sn  证书SN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "normal-rsa-sn-base64-salg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_26(String str, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用正常RSA证书SN签名，公钥验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String[] split = str.split("%");
        String sn = split[0];
        String sPublickey = split[1];
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, sn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, null, alg, pSignData, sPublickey);
            if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:使用作废RSA证书SN签名，公钥验签
     *
     * @param sn  证书SN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "revoke-rsa-sn-base64-salg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_27(String str, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用作废RSA证书SN签名，公钥验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String[] split = str.split("%");
        String sn = split[0];
        String sPublickey = split[1];
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, sn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, null, alg, pSignData, sPublickey);
            if (upkiResult1.getReturnCode() != -100108) {
                if (!"0219373e13cf29".equals(sn) && !("012c12835bad69").equals(sn)) {
                    Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail("Raw验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:使用过期RSA证书SN签名，公钥验签
     *
     * @param sn  证书SN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "expire-rsa-sn-base64-salg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_28(String str, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用过期RSA证书SN签名，公钥验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String[] split = str.split("%");
        String sn = split[0];
        String sPublickey = split[1];
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, sn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, null, alg, pSignData, sPublickey);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != -100106) {
                Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:使用不受信任RSA证书SN签名，公钥验签
     *
     * @param sn  证书SN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "nottrust-rsa-sn-base64-salg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_29(String str, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用不受信任RSA证书SN签名，公钥验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String[] split = str.split("%");
        String sn = split[0];
        String sPublickey = split[1];
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        if (sn.equals("50e66bcca4")) {
            return;
        }
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, sn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, null, alg, pSignData, sPublickey);
            if (upkiResult1.getReturnCode() != -100124) {
                Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:使用正常SM2证书DN签名，公钥验签
     *
     * @param dn  证书DN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "normal-sm2-dn-base64-salg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_30(String str, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用正常SM2证书DN签名，公钥验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String[] split = str.split("%");
        String dn = split[0];
        String sPublickey = split[1];
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, null, alg, pSignData, sPublickey);
            if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                if (upkiResult1.getReturnCode() != -100130 || !"SHA1".equals(alg)) {
                    Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("Raw验摘要（RawVerifyHash）：国密证书验签时不支持SHA1算法");
            }
        } catch (Exception e) {
            Assert.fail("Raw验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:使用作废SM2证书DN签名，公钥验签
     *
     * @param dn  证书DN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "revoke-sm2-dn-base64-salg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_31(String str, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用作废SM2证书DN签名，公钥验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String[] split = str.split("%");
        String dn = split[0];
        String sPublickey = split[1];
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, null, alg, pSignData, sPublickey);
            if (upkiResult1.getReturnCode() != -100108) {
                if (upkiResult1.getReturnCode() != -100130 || !"SHA1".equals(alg)) {
                    Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("Raw验摘要（RawVerifyHash）：国密证书验签时不支持SHA1算法");
            }
        } catch (Exception e) {
            Assert.fail("Raw验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:使用过期SM2证书DN签名，公钥验签
     *
     * @param dn  证书DN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "expire-sm2-dn-base64-salg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_32(String str, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用过期SM2证书DN签名，公钥验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String[] split = str.split("%");
        String dn = split[0];
        String sPublickey = split[1];
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, null, alg, pSignData, sPublickey);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != -100106) {
                if (upkiResult1.getReturnCode() != -100130 || !"SHA1".equals(alg)) {
                    Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("Raw验摘要（RawVerifyHash）：国密证书验签时不支持SHA1算法");
            }
        } catch (Exception e) {
            Assert.fail("Raw验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }


    /**
     * Raw验摘要（rawVerifyHash）:使用正常SM2证书SN签名，公钥验签
     *
     * @param sn  证书SN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "normal-sm2-sn-base64-salg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_33(String str, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用正常SM2证书SN签名，公钥验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String[] split = str.split("%");
        String sn = split[0];
        String sPublickey = split[1];
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, sn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, null, alg, pSignData, sPublickey);
            if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                if (upkiResult1.getReturnCode() != -100130 && "SHA1".equals(alg)) {
                    Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("Raw验摘要（RawVerifyHash）：国密证书验签时不支持SHA1算法");
            }
        } catch (Exception e) {
            Assert.fail("Raw验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:使用作废SM2证书SN签名，公钥验签
     *
     * @param sn  证书SN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "revoke-sm2-sn-base64-salg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_34(String str, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用作废SM2证书SN签名，公钥验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String[] split = str.split("%");
        String sn = split[0];
        String sPublickey = split[1];
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, sn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, null, alg, pSignData, sPublickey);
            if (upkiResult1.getReturnCode() != -100108) {
                if (upkiResult1.getReturnCode() != -100130 && "SHA1".equals(alg)) {
                    Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("Raw验摘要（RawVerifyHash）：国密证书验签时不支持SHA1算法");
            }
        } catch (Exception e) {
            Assert.fail("Raw验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:使用过期SM2证书SN签名，公钥验签
     *
     * @param sn  证书SN
     * @param alg 摘要算法
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "expire-sm2-sn-base64-salg", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_35(String str, String alg) {
        System.out.println("Raw验摘要（rawVerifyHash）:使用过期SM2证书SN签名，公钥验签");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String[] split = str.split("%");
        String sn = split[0];
        String sPublickey = split[1];
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, sn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, null, alg, pSignData, sPublickey);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != -100106) {
                if (upkiResult1.getReturnCode() != -100130 && "SHA1".equals(alg)) {
                    Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("Raw验摘要（RawVerifyHash）：国密证书验签时不支持SHA1算法");
            }
        } catch (Exception e) {
            Assert.fail("Raw验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:原文为空或null
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_36(String str) {
        System.out.println("Raw验摘要（rawVerifyHash）:原文为空或null");

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
            upkiResult = agent.rawSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(str, dn, alg, pSignData, null);
            if (upkiResult1.getReturnCode() != -1011 && upkiResult1.getReturnCode() != -100101) {
                Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:密文为空或null
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_37(String pSignData) {
        System.out.println("Raw验摘要（rawVerifyHash）:密文为空或null");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        String alg = "SHA1";
        UpkiResult upkiResult1 = null;
        String digestData = null;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult1 = agent.rawVerifyHash(digestData, dn, alg, pSignData, null);
            if (upkiResult1.getReturnCode() != -1011 && upkiResult1.getReturnCode() != -100004) {
                Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:摘要算法为空或null
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_38(String salg) {
        System.out.println("Raw验摘要（rawVerifyHash）:摘要算法为空或null");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        String alg = "SHA256";
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, dn, salg, pSignData, null);
            if (upkiResult1.getReturnCode() != -100101) {
                Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:DN和Base64公钥同时为空或null
     */
    @Test(groups = "abcjew.rawverifyhash.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawVerifyHash_39(String str) {
        System.out.println("Raw验摘要（rawVerifyHash）:DN和Base64公钥同时为空或null");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        String alg = "SHA256";
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, str, alg, pSignData, str);
            if (upkiResult1.getReturnCode() != -100205) {
                Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:验签DN与签名使用DN不匹配
     */
    @Test(groups = "abcjew.rawverifyhash.normal")
    public void testRawVerifyHash_40() {
        System.out.println("Raw验摘要（rawVerifyHash）:验签DN与签名使用DN不匹配");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        String dn2 = "C=cn,O=INFOSEC Technologies RSA,CN=R018信安世纪";
        String alg = "SHA1";
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String digestData = null;
        String pSignData;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, dn2, alg, pSignData, null);
            if (upkiResult1.getReturnCode() != -100104) {
                Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:摘要算法内容错误
     */
    @Test(groups = "abcjew.rawverifyhash.normal")
    public void testRawVerifyHash_41() {
        System.out.println("Raw验摘要（rawVerifyHash）:摘要算法内容错误");

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
            upkiResult = agent.rawSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            upkiResult1 = agent.rawVerifyHash(digestData, dn, "alg", pSignData, null);
            if (upkiResult1.getReturnCode() != -100101) {
                Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }

    /**
     * Raw验摘要（rawVerifyHash）:密文篡改
     */
    @Test(groups = "abcjew.rawverifyhash.normal")
    public void testRawVerifyHash_42() {
        System.out.println("Raw验摘要（rawVerifyHash）:密文篡改");

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
            upkiResult = agent.rawSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }

        try {
            pSignData = upkiResult.getResults().get("sign_text").toString();
            pSignData = Utils.modifyData(pSignData, 5, 10, "abcde");
            upkiResult1 = agent.rawVerifyHash(digestData, dn, alg, pSignData, null);
            if (upkiResult1.getReturnCode() != -100104) {
                Assert.fail("Raw验摘要失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw验摘要失败：" + e.getMessage() + upkiResult1.getReturnCode());
        }
    }
}
