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
import java.util.Random;

/**
 * @author suiyixin
 * @ClassName: TestRawVerify
 * @date 2020-03-05 9:40
 * @Description: <p>用例覆盖点：</p>
 * <p>1）sPublickey公钥证书为null，其他参数均正确</p>
 * <p>2）sPublickey公钥证书为空字符串，其他参数均正确</p>
 * <p>3）pOrgData原文不一致</p>
 * <p>4）pOrgData原文为null</p>
 * <p>5）pOrgData原文为空</p>
 * <p>6）pOrgData大原文</p>
 * <p>7）sCertDN密钥传证书机构代码</p>
 * <p>8）sCertDN密钥不存在</p>
 * <p>9）sCertDN密钥与签名不一致</p>
 * <p>10）sCertDN为null，sPublickey公钥证书正确</p>
 * <p>11）sCertDN为空字符串，sPublickey公钥证书正确</p>
 * <p>12）过期证书DN</p>
 * <p>13）作废证书DN</p>
 * <p>14）不受信任证书DN</p>
 * <p>15）黑名单证书DN</p>
 * <p>16）sDigestAlg摘要算法为空</p>
 * <p>17）sDigestAlg摘要算法为null</p>
 * <p>18）sDigestAlg摘要算法不存在</p>
 * <p>19）sDigestAlg摘要算法与签名不一致</p>
 * <p>20）sDigestAlg摘要算法小写</p>
 * <p>21）pSignData签名值被篡改</p>
 * <p>22）pSignData签名值为空或者null</p>
 * <p>23）sPublickey公钥证书与签名不一致</p>
 * <p>24）sCertDN和sPublickey均为空/null</p>
 * <p>25）sCertDN和sPublickey均输入，使用sPublickey</p>
 */
public class TestRawVerify {
    static String ip, port, password;
    static String host, sftp_port, sftp_password, sftp_user;
    Random random = new Random();

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
     * 裸验，公钥证书为null，其他参数均正确
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "normal-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_01(String alg, String dn) {
        System.out.println("裸验(rawVerify),参数均正确，公钥证书为null传DN");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.rawVerify(pOrgData, dn, alg, signresult, null);
            if (verify.getBoolResult() != true || verify.getReturnCode() != 0
                    || !"success".equals(verify.getReturnContent())) {
                Assert.fail(" 金E卫ABCJEW裸验，测试公钥证书为空使用DN，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW裸验，测试公钥证书为空使用DN，抛异常！" + e.getMessage());
        }
    }

    /**
     * 裸验，公钥证书为空字符串，其他参数均正确
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "normal-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_02(String alg, String dn) {
        System.out.println("裸验(rawVerify),参数均正确，公钥证书为空传DN");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.rawVerify(pOrgData, dn, alg, signresult, "");
            if (verify.getBoolResult() != true || verify.getReturnCode() != 0
                    || !"success".equals(verify.getReturnContent())) {
                Assert.fail(" 金E卫ABCJEW裸验，测试公钥证书为null使用DN，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW裸验，测试公钥证书为null使用DN，抛异常！" + e.getMessage());
        }
    }

    /**
     * 裸验，原文不一致
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "normal-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_03(String alg, String dn) {
        System.out.println("裸验(rawVerify),原文不一致");
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign("aaa".getBytes(), dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();

            verify = agent.rawVerify("basdd".getBytes(), dn, alg, signresult, null);
            if (verify.getReturnCode() != -100104) {
                Assert.fail(" 金E卫ABCJEW裸验，测试原文不一致，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW裸验，测试原文不一致，抛异常！" + e.getMessage());
        }
    }

    /**
     * 裸验，原文为null
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "normal-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_04(String alg, String dn) {
        System.out.println("裸验(rawVerify),原文为null");
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign("".getBytes(), dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();

            verify = agent.rawVerify(null, dn, alg, signresult, null);
            if (verify.getReturnCode() != -1027) {
                Assert.fail(" 金E卫ABCJEW裸验，测试原文为null，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW裸验，测试原文为null，抛异常！" + e.getMessage());
        }
    }

    /**
     * 裸验，原文为空
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "normal-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_05(String alg, String dn) {
        System.out.println("裸验(rawVerify),原文为空");
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign("".getBytes(), dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();

            verify = agent.rawVerify("".getBytes(), dn, alg, signresult, null);
            boolean code = verify.getBoolResult();
            if (verify.getReturnCode() != -1027) {
                if (verify.getReturnCode() != 0) {
                    Assert.fail(" 金E卫ABCJEW裸验，测试原文为空，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
                }
                Reporter.log("金E卫ABCJEW裸验，原文传空字符串，验签成功");
            }

        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW裸验，测试原文为空，抛异常！" + e.getMessage());
        }
    }

    /**
     * 裸验，sCertDN传证书机构代码
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "normal-alg-bankcode", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_06(String alg, String bankcode) {
        System.out.println("裸验(rawVerify),sCertDN传证书机构代码");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, bankcode, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();

            verify = agent.rawVerify(pOrgData, bankcode, alg, signresult, null);
            if (verify.getBoolResult() != true || verify.getReturnCode() != 0
                    || !"success".equals(verify.getReturnContent())) {
                Assert.fail(" 金E卫ABCJEW裸验，测试传公钥证书机构代码，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW裸验，测试传公钥证书机构代码，抛异常！" + e.getMessage());
        }
    }

    /**
     * 裸验，传不存在的密钥
     */
    @Test(groups = "abcjew.rawverify.normal")
    public void testrawVerify_07() {
        System.out.println("裸验(rawVerify),传不存在的密钥");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, "C=cn,O=INFOSEC Technologies RSA,CN=SS019normal", "SHA256");
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.rawVerify(pOrgData, "bucunzaidemiyue", "SHA256", signresult, null);
            if (verify.getBoolResult() != false || verify.getReturnCode() != -100224) {
                Assert.fail(" 金E卫ABCJEW裸验，测试传不存在的密钥，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW裸验，测试传不存在的密钥，抛异常！" + e.getMessage());
        }
    }

    /**
     * 裸验，传与签名不一致的密钥
     */
    @Test(groups = "abcjew.rawverify.normal")
    public void testrawVerify_08() {
        System.out.println("裸验(rawVerify),传与签名时不一致的密钥");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, "C=cn,O=INFOSEC Technologies RSA,CN=SS019normal", "SHA256");
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.rawVerify(pOrgData, "C=cn,O=INFOSEC Technologies RSA,CN=S019源于信至于安", "SHA256", signresult,
                    null);
            if (verify.getBoolResult() != false || verify.getReturnCode() != -100104) {
                Assert.fail(" 金E卫ABCJEW裸验，测试传与签名不一致的密钥，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW裸验，测试传与签名不一致的密钥，抛异常！" + e.getMessage());
        }
    }

    /**
     * 裸验，DN为null，使用正确的sPublickey公钥证书
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "normal-alg-dn-cert", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_09(String alg, String dn, String cert) {
        System.out.println("裸验(rawVerify),DN为null传公钥证书");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.rawVerify(pOrgData, null, alg, signresult, cert);

            if (verify.getBoolResult() != true || verify.getReturnCode() != 0
                    || !"success".equals(verify.getReturnContent())) {
                Assert.fail(" 金E卫ABCJEW裸验，测试DN为null传公钥证书，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW裸验，测试DN为null传公钥证书，抛异常！" + e.getMessage());
        }
    }

    /**
     * 裸验，DN为空字符串，使用正确的sPublickey公钥证书
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "normal-alg-dn-cert", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_10(String alg, String dn, String cert) {
        System.out.println("裸验(rawVerify),DN为空传公钥证书");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.rawVerify(pOrgData, "", alg, signresult, cert);

            if (verify.getBoolResult() != true || verify.getReturnCode() != 0
                    || !"success".equals(verify.getReturnContent())) {
                Assert.fail(" 金E卫ABCJEW裸验，测试DN为空字符串传公钥证书，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW裸验，测试DN为空字符串传公钥证书，抛异常！" + e.getMessage());
        }
    }

    /**
     * 裸验，过期证书
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "expire-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_11(String alg, String dn) {
        System.out.println("裸验(rawVerify),证书过期");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.rawVerify(pOrgData, dn, alg, signresult, null);
            if (verify.getBoolResult() != false || verify.getReturnCode() != -100106) {
                Assert.fail(" 金E卫ABCJEW裸验，测试过期证书，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW裸验，测试过期证书，抛异常！" + e.getMessage());
        }
    }

    /**
     * 裸验，作废证书
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "revoke-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_12(String alg, String dn) {
        System.out.println("裸验(rawVerify),证书作废");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            if (!("C=CN,O=infosec,OU=test3,CN=C020revokeMatchingAnyCrlfbd").equals(dn)
                    && !("C=CN,O=infosec,CN=C020revokedNocrlfile").equals(dn)) {
                verify = agent.rawVerify(pOrgData, dn, alg, signresult, null);
                if (verify.getBoolResult() != false || verify.getReturnCode() != -100108) {
                    Assert.fail(" 金E卫ABCJEW裸验，测试作废证书，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW裸验，测试作废证书，抛异常！" + e.getMessage());
        }

    }

    /**
     * 裸验，不受信任证书
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "nottrust-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_13(String alg, String dn) {
        System.out.println("裸验(rawVerify),证书不受信任");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.rawVerify(pOrgData, dn, alg, signresult, null);
            if (verify.getBoolResult() != false || verify.getReturnCode() != -100124) {
                Assert.fail(" 金E卫ABCJEW裸验，测试不受信任证书，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW裸验，测试不受信任证书，抛异常！" + e.getMessage());
        }
    }

    /**
     * 裸验，黑名单证书
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "blacklist-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_14(String alg, String dn) {
        System.out.println("裸验(rawVerify),证书处于黑名单");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.rawVerify(pOrgData, dn, alg, signresult, null);
            if (verify.getBoolResult() != false || verify.getReturnCode() != -100226) {
                Assert.fail(" 金E卫ABCJEW裸验，测试黑名单证书，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW裸验，测试黑名单证书，抛异常！" + e.getMessage());
        }
    }

    /**
     * 裸验，Alg为空
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "normal-dn", dataProviderClass = NetSignDataProvider.class)
    public void testrawVerify_15(String dn) {
        System.out.println("裸验(rawVerify),摘要算法Alg为空");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, dn, "");
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.rawVerify(pOrgData, dn, "", signresult, null);
            if (verify.getBoolResult() != true || verify.getReturnCode() != 0
                    || !"success".equals(verify.getReturnContent())) {
                Assert.fail(" 金E卫ABCJEW裸验，测试摘要算法为空，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW，测试摘要算法为空，抛异常！" + e.getMessage());
        }
    }

    /**
     * 裸验，Alg为null
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "normal-dn", dataProviderClass = NetSignDataProvider.class)
    public void testrawVerify_16(String dn) {
        System.out.println("裸验(rawVerify),摘要算法Alg为null");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, dn, null);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.rawVerify(pOrgData, dn, null, signresult, null);
            if (verify.getBoolResult() != true || verify.getReturnCode() != 0
                    || !"success".equals(verify.getReturnContent())) {
                Assert.fail(" 金E卫ABCJEW裸验，测试摘要算法为null，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW裸验，测试摘要算法为null，抛异常！" + e.getMessage());
        }
    }

    /**
     * 裸验，Alg不存在
     */
    @Test(groups = "abcjew.rawverify.normal")
    public void testrawVerify_17() {
        System.out.println("裸验(rawVerify),摘要算法Alg不存在");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, "C=cn,O=INFOSEC Technologies RSA,CN=R018normal", "SHA1");
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.rawVerify(pOrgData, "C=cn,O=INFOSEC Technologies RSA,CN=R018normal", "sss", signresult,
                    null);
            if (verify.getBoolResult() != false || verify.getReturnCode() != -100112) {
                Assert.fail(" 金E卫ABCJEW裸验，测试不存在的摘要算法，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW裸验，测试不存在的摘要算法，抛异常！" + e.getMessage());
        }
    }

    /**
     * 裸验，Alg与签名不一致
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "normal-dn", dataProviderClass = NetSignDataProvider.class)
    public void testrawVerify_18(String dn) {
        System.out.println("裸验(rawVerify),摘要算法Alg与签名不一致");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, dn, "SHA1");
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.rawVerify(pOrgData, dn, "SHA256", signresult, null);
            if (verify.getBoolResult() != false || verify.getReturnCode() != -100104) {
                Assert.fail(" 金E卫ABCJEW裸验，测试与签名时不一致的摘要算法，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW裸验，测试与签名时不一致的摘要算法，抛异常！" + e.getMessage());
        }
    }

    /**
     * 裸验，Alg小写
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "normal-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_19(String alg, String dn) {
        System.out.println("裸验(rawVerify),摘要算法Alg小写");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            String littlealg = alg.toLowerCase();
            sign = agent.rawSign(pOrgData, dn, littlealg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.rawVerify(pOrgData, dn, littlealg, signresult, null);
            if (verify.getBoolResult() != true || verify.getReturnCode() != 0) {
                if (verify.getReturnCode() != -100112) {
                    Assert.fail(" 金E卫ABCJEW裸验，测试小写摘要算法，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
                }
                Reporter.log("金E卫ABCJEW裸验，小写摘要算法，验签失败，不支持小写");
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW裸验，测试小写摘要算法，抛异常！" + e.getMessage());
        }
    }

    /**
     * 裸验，签名值被篡改
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "normal-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_20(String alg, String dn) {
        System.out.println("裸验(rawVerify),签名值被篡改");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            String new_sign_result = "";
            sign = agent.rawSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String sign_result = sign_text.toString();
            // 修改签名结果
            StringBuilder sb = new StringBuilder(sign_result);
            sb.replace(8, 10, "2a");
            new_sign_result = sb.toString();
            verify = agent.rawVerify(pOrgData, dn, alg, new_sign_result, null);
            if (verify.getBoolResult() != false || verify.getReturnCode() != -100104) {
                Assert.fail(" 金E卫ABCJEW裸验，测试被篡改的签名值，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW裸验，测试被篡改的签名值，抛异常！" + e.getMessage());
        }
    }

    /**
     * 裸验，签名值为空或者null
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_21(String sign) {
        System.out.println("裸验(rawVerify),签名值为空或null");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult verify;
            verify = agent.rawVerify(pOrgData, "C=cn,O=INFOSEC Technologies RSA,CN=R018normal", "SHA256", sign, null);
            if (verify.getReturnCode() != -1027) {
                if (verify.getReturnCode() != -100104) {
                    Assert.fail(" 金E卫ABCJEW裸验，测试签名值为空或者null，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW裸验，测试签名值为空或者null，抛异常！" + e.getMessage());
        }
    }

    /**
     * 裸验，公钥证书与签名值不一致
     */
    @Test(groups = "abcjew.rawverify.normal")
    public void testrawVerify_22() {
        System.out.println("裸验(rawVerify),公钥证书与签名值不一致");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, "C=cn,O=INFOSEC Technologies RSA,CN=SS019normal", "SHA256");
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            String sPublickey = "MIICUzCCAfagAwIBAgIGALceda" +
                    "+AMAwGCCqBHM9VAYN1BQAwUTELMAkGA1UEBhMCY24xKTAnBgNVBAoMIElORk9TRUMgVGVjaG5vbG9naWVzIFNNMklEX1NVQkNBMRcwFQYDVQQDDA5hcHBTTTJJRF9TVUJDQTAeFw0xODA1MDMwNTUzNDBaFw0yNjA0MTkwNzE2NTBaMEMxCzAJBgNVBAYTAmNuMSEwHwYDVQQKDBhJTkZPU0VDIFRlY2hub2xvZ2llcyBSU0ExETAPBgNVBAMMCFMwMTlfIyEkMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAErFvPNyY3l93bHRyFpwptEV0cEvR/QjrkGma1DRjcY6beWW5wmlrcoBKYW3h2RALrP+r4nfroRSD7yIpjveS/4aOBxTCBwjAfBgNVHSMEGDAWgBRQlLwbc3s6aiWtLrw91rqo+4hB9DAJBgNVHRMEAjAAMGgGA1UdHwRhMF8wXaBboFmkVzBVMQ0wCwYDVQQDDARjcmwzMQwwCgYDVQQLDANjcmwxKTAnBgNVBAoMIElORk9TRUMgVGVjaG5vbG9naWVzIFNNMklEX1NVQkNBMQswCQYDVQQGEwJjbjALBgNVHQ8EBAMCB4AwHQYDVR0OBBYEFH2gnd6tjMZLI6gYoSHEq8Lc5zt8MAwGCCqBHM9VAYN1BQADSQAwRgIhAOhonE4h5W9BGPwEFqwwDpv+0XgydohmzTupwRGGQcdvAiEA2EnJZ3+6UUDxzZX6mxiXDnS5M32v6wf29u3B/YjoPNg=";
            verify = agent.rawVerify(pOrgData, null, "SHA256", signresult, sPublickey);
            if (verify.getBoolResult() != false || verify.getReturnCode() != -100104) {
                Assert.fail(" 金E卫ABCJEW裸验，测试公钥证书与签名值不一致，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW裸验，测试公钥证书与签名值不一致，抛异常！" + e.getMessage());
        }
    }

    /**
     * 裸验，DN和公钥证书均为空/null
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_23(String cert) {
        System.out.println("裸验(rawVerify),DN和公钥证书均为空/null");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, "C=cn,O=INFOSEC Technologies RSA,CN=SS019normal", "SHA256");
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.rawVerify(pOrgData, cert, "SHA256", signresult, cert);
            if (verify.getBoolResult() != false || verify.getReturnCode() != -100224) {
                Assert.fail(" 金E卫ABCJEW裸验，测试DN和公钥证书传空或null，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW裸验，测试DN和公钥证书传空或null，抛异常！" + e.getMessage());
        }
    }

    /**
     * 裸验，DN和公钥证书均输入，使用正确的sPublickey公钥证书
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "normal-alg-dn-cert", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_24(String alg, String dn, String cert) {
        System.out.println("裸验(rawVerify),DN和公钥证书均输入，使用正确的sPublickey公钥证书");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.rawVerify(pOrgData, "CN=bucunzaidemiyue", alg, signresult, cert);

            if (verify.getBoolResult() != true || verify.getReturnCode() != 0
                    || !"success".equals(verify.getReturnContent())) {
                Assert.fail(" 金E卫ABCJEW裸验，测试DN和公钥证书均输入是否使用公钥证书，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW裸验,测试DN和公钥证书均输入是否使用公钥证书，抛异常！" + e.getMessage());
        }
    }
}
