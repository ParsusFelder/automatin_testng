package qa.infosec.testng.netsign.upki;

import cn.com.infosec.netsign.agent.UpkiAgent;
import cn.com.infosec.netsign.agent.UpkiResult;
import org.testng.Assert;
import org.testng.annotations.Test;
import qa.infosec.testng.netsign.dataprovider.NetSignDataProvider;
import qa.infosec.testng.netsign.dataprovider.util.ParameterUtil;
import qa.infosec.testng.netsign.dataprovider.util.ParseFile;
import qa.infosec.testng.netsign.dataprovider.util.SFTPFile;
import qa.infosec.testng.netsign.dataprovider.util.Utils;
import qa.infosec.testng.netsign.init.NetSignServerInit;

import java.security.cert.X509Certificate;
import java.util.Map;

/**
 * @author zhaoyongzhi
 * @ClassName: TestRawVerifyByX509Cert
 * @date 2020-04-14 09:22
 * @Description: 传证书对象验裸签
 * <p>用例覆盖点：</p>
 * <p>1）使用RSA证书验签名，证书状态正常</p>
 * <p>2）使用RSA证书验签名，证书状态过期</p>
 * <p>3）使用RSA证书验签名，证书状态作废</p>
 * <p>4）使用SM2证书验签名，证书状态正常</p>
 * <p>5）使用SM2证书验签名，证书状态过期</p>
 * <p>6）使用SM2证书验签名，证书状态作废</p>
 * <p>7）原文为null</p>
 * <p>8）密文为null</p>
 * <p>9）密文为空字符</p>
 * <p>10）证书为空字符</p>
 */
@Test(groups = "abcjew.rawverifybyx509cert")
public class TestRawVerifyByX509Cert {
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
     * 使用RSA证书验签名，证书状态正常
     */
    @Test(groups = "abcjew.rawverifybyx509cert.normal", dataProvider = "normal-rsa-cert",
            dataProviderClass = NetSignDataProvider.class)
    public void testRawVerifyByX509Cert_01(X509Certificate cert) {
        System.out.println("传证书内容验裸签（rawVerify）：使用RSA证书验签名，证书状态正常");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        String dn = cert.getSubjectDN().getName();
        String dalg = "sha1";
        UpkiResult upkiResult = agent.rawSign(plainText, dn, dalg);
        String sign_text = upkiResult.getResults().get("sign_text").toString();

        try {
            UpkiResult upkiResult1 = agent.rawVerify(plainText, sign_text, cert);
            if (upkiResult1.getReturnCode() != 0) {
                Assert.fail("传证书内容验裸签（rawVerify）失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("传证书内容验裸签（rawVerify）失败：" + e.getMessage());
        }
    }

    /**
     * 使用RSA证书验签名，证书状态过期
     */
    @Test(groups = "abcjew.rawverifybyx509cert.normal", dataProvider = "expire-rsa-cert",
            dataProviderClass = NetSignDataProvider.class)
    public void testRawVerifyByX509Cert_02(X509Certificate cert) {
        System.out.println("传证书内容验裸签（rawVerify）：使用RSA证书验签名，证书状态过期");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        String dn = cert.getSubjectDN().getName();
        String dalg = "sha1";
        UpkiResult upkiResult = agent.rawSign(plainText, dn, dalg);
        String sign_text = upkiResult.getResults().get("sign_text").toString();

        try {
            UpkiResult upkiResult1 = agent.rawVerify(plainText, sign_text, cert);
            if (upkiResult1.getReturnCode() != -100106) {
                Assert.fail("传证书内容验裸签（rawVerify）失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("传证书内容验裸签（rawVerify）失败：" + e.getMessage());
        }
    }

    /**
     * 使用RSA证书验签名，证书状态作废
     */
    @Test(groups = "abcjew.rawverifybyx509cert.normal", dataProvider = "revoke-rsa-cert",
            dataProviderClass = NetSignDataProvider.class)
    public void testRawVerifyByX509Cert_03(X509Certificate cert) {
        System.out.println("传证书内容验裸签（rawVerify）：使用RSA证书验签名，证书状态作废");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        String dn = cert.getSubjectDN().getName();
        String dalg = "sha1";
        if ("C=CN,O=infosec,OU=test3,CN=C020revokeMatchingAnyCrlfbd".equals(dn) || "C=CN,O=infosec,CN=C020revokedNocrlfile".equals(dn) ) {
            return;
        }
        UpkiResult upkiResult = agent.rawSign(plainText, dn, dalg);
        String sign_text = upkiResult.getResults().get("sign_text").toString();

        try {
            UpkiResult upkiResult1 = agent.rawVerify(plainText, sign_text, cert);
            if (upkiResult1.getReturnCode() != -100108) {
                Assert.fail("传证书内容验裸签（rawVerify）失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("传证书内容验裸签（rawVerify）失败：" + e.getMessage());
        }
    }

    /**
     * 使用SM2证书验签名，证书状态正常
     */
    @Test(groups = "abcjew.rawverifybyx509cert.normal", dataProvider = "normal-sm2-cert",
            dataProviderClass = NetSignDataProvider.class)
    public void testRawVerifyByX509Cert_04(X509Certificate cert) {
        System.out.println("传证书内容验裸签（rawVerify）：使用SM2证书验签名，证书状态正常");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        String dn = cert.getSubjectDN().getName();
        String dalg = "sm3";
        UpkiResult upkiResult = agent.rawSign(plainText, dn, dalg);
        String sign_text = upkiResult.getResults().get("sign_text").toString();

        try {
            UpkiResult upkiResult1 = agent.rawVerify(plainText, sign_text, cert);
            if (upkiResult1.getReturnCode() != 0) {
                Assert.fail("传证书内容验裸签（rawVerify）失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("传证书内容验裸签（rawVerify）失败：" + e.getMessage());
        }
    }

    /**
     * 使用SM2证书验签名，证书状态过期
     */
    @Test(groups = "abcjew.rawverifybyx509cert.normal", dataProvider = "expire-sm2-cert",
            dataProviderClass = NetSignDataProvider.class)
    public void testRawVerifyByX509Cert_05(X509Certificate cert) {
        System.out.println("传证书内容验裸签（rawVerify）：使用SM2证书验签名，证书状态过期");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        String dn = cert.getSubjectDN().getName();
        String dalg = "sm3";
        UpkiResult upkiResult = agent.rawSign(plainText, dn, dalg);
        String sign_text = upkiResult.getResults().get("sign_text").toString();

        try {
            UpkiResult upkiResult1 = agent.rawVerify(plainText, sign_text, cert);
            if (upkiResult1.getReturnCode() != -100106) {
                Assert.fail("传证书内容验裸签（rawVerify）失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("传证书内容验裸签（rawVerify）失败：" + e.getMessage());
        }
    }

    /**
     * 使用SM2证书验签名，证书状态作废
     */
    @Test(groups = "abcjew.rawverifybyx509cert.normal", dataProvider = "revoke-sm2-cert",
            dataProviderClass = NetSignDataProvider.class)
    public void testRawVerifyByX509Cert_06(X509Certificate cert) {
        System.out.println("传证书内容验裸签（rawVerify）：使用SM2证书验签名，证书状态作废");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        String dn = cert.getSubjectDN().getName();
        String dalg = "sm3";
        UpkiResult upkiResult = agent.rawSign(plainText, dn, dalg);
        String sign_text = upkiResult.getResults().get("sign_text").toString();

        try {
            UpkiResult upkiResult1 = agent.rawVerify(plainText, sign_text, cert);
            if (upkiResult1.getReturnCode() != -100108) {
                Assert.fail("传证书内容验裸签（rawVerify）失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("传证书内容验裸签（rawVerify）失败：" + e.getMessage());
        }
    }

    /**
     * 原文为null
     */
    @Test(groups = "abcjew.rawverifybyx509cert.normal", dataProvider = "normal-rsa-cert",
            dataProviderClass = NetSignDataProvider.class)
    public void testRawVerifyByX509Cert_07(X509Certificate cert) {
        System.out.println("传证书内容验裸签（rawVerify）：原文为null");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        String dn = cert.getSubjectDN().getName();
        String dalg = "sha1";
        UpkiResult upkiResult = agent.rawSign(plainText, dn, dalg);
        String sign_text = upkiResult.getResults().get("sign_text").toString();

        try {
            UpkiResult upkiResult1 = agent.rawVerify(null, sign_text, cert);
            if (upkiResult1.getReturnCode() != -1027) {
                Assert.fail("传证书内容验裸签（rawVerify）失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("传证书内容验裸签（rawVerify）失败：" + e.getMessage());
        }
    }

    /**
     * 密文为null
     */
    @Test(groups = "abcjew.rawverifybyx509cert.normal", dataProvider = "normal-rsa-cert",
            dataProviderClass = NetSignDataProvider.class)
    public void testRawVerifyByX509Cert_08(X509Certificate cert) {
        System.out.println("传证书内容验裸签（rawVerify）：密文为null");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        String dn = cert.getSubjectDN().getName();
        String dalg = "sha1";
        UpkiResult upkiResult = agent.rawSign(plainText, dn, dalg);
        String sign_text = upkiResult.getResults().get("sign_text").toString();

        try {
            UpkiResult upkiResult1 = agent.rawVerify(plainText, null, cert);
            if (upkiResult1.getReturnCode() != -1027) {
                Assert.fail("传证书内容验裸签（rawVerify）失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("传证书内容验裸签（rawVerify）失败：" + e.getMessage());
        }
    }

    /**
     * 密文为空字符
     */
    @Test(groups = "abcjew.rawverifybyx509cert.normal", dataProvider = "normal-rsa-cert",
            dataProviderClass = NetSignDataProvider.class)
    public void testRawVerifyByX509Cert_09(X509Certificate cert) {
        System.out.println("传证书内容验裸签（rawVerify）：密文为空字符");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        String dn = cert.getSubjectDN().getName();
        String dalg = "sha1";
        UpkiResult upkiResult = agent.rawSign(plainText, dn, dalg);
        String sign_text = upkiResult.getResults().get("sign_text").toString();

        try {
            UpkiResult upkiResult1 = agent.rawVerify(plainText, "", cert);
            if (upkiResult1.getReturnCode() != -100104) {
                Assert.fail("传证书内容验裸签（rawVerify）失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("传证书内容验裸签（rawVerify）失败：" + e.getMessage());
        }
    }

    /**
     * 证书为空字符
     */
    @Test(groups = "abcjew.rawverifybyx509cert.normal", dataProvider = "normal-rsa-cert",
            dataProviderClass = NetSignDataProvider.class)
    public void testRawVerifyByX509Cert_10(X509Certificate cert) {
        System.out.println("传证书内容验裸签（rawVerify）：密文为空字符");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        String dn = cert.getSubjectDN().getName();
        String dalg = "sha1";
        UpkiResult upkiResult = agent.rawSign(plainText, dn, dalg);
        String sign_text = upkiResult.getResults().get("sign_text").toString();

        try {
            UpkiResult upkiResult1 = agent.rawVerify(plainText, sign_text, "");
            if (upkiResult1.getReturnCode() != -1) {
                Assert.fail("传证书内容验裸签（rawVerify）失败：" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("传证书内容验裸签（rawVerify）失败：" + e.getMessage());
        }
    }
}
