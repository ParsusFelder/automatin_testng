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
 * @author suiyixin
 * @ClassName: TestDetachedVerify
 * @date 2020-03-10 11:40
 * @Description:
 * <p>用例覆盖点：</p>
 * 因为此detached验签不支持SHA1和SHA256算法，故将RSA和SM2分为2个方法
 * <p>1）RSA证书验签</p>
 * <p>2）SM2证书验签</p>
 * <p>3）签名值被篡改</p>
 * <p>4）签名值为空或者null</p>
 * <p>5）签名证书已过期</p>
 * <p>6）签名证书已作废</p>
 * <p>7）签名证书不受信任</p>
 * <p>8）验签证书不存在</p>
 * <p>9）密钥传RSA证书sn的签名值</p>
 * <p>10）密钥传SM2证书sn的签名值</p>
 * <p>11）使用默认摘要算法的签名值</p>
 * <p>12）使用RSA类型小写摘要算法的签名值</p>
 * <p>13）使用SM2类型小写摘要算法的签名值</p>
 * <p>14）原文不一致</p>
 * <p>15）原文为null</p>
 * <p>16）原文为空</p>
 */
public class TestDetachedVerify {
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
     * 由于此接口国密验签使用SHA1、SHA256算法报错，故将RSA和SM2区分两个方法
     * Detached验签，参数均正常,RSA
     */
    @Test(groups = "abcjew.detachedverify.normal", dataProvider = "rsadn-normal-alg", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedVerify_01(String dn, String alg) {
        System.out.println("Detached验签(detachedVerify),参数均正常,RSA证书");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.detachedSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.detachedVerify(pOrgData, signresult);
            if (verify.getBoolResult() != true || verify.getReturnCode() != 0
                    || !"success".equals(verify.getReturnContent())) {
                Assert.fail(" 金E卫ABCJEW-detached验签，测试传参均正常RSA，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-detached验签，测试传参均正常RSA，抛异常！" + e.getMessage());
        }
    }

    /**
     * Detached验签，参数均正常,SM2
     */
    @Test(groups = "abcjew.detachedverify.normal", dataProvider = "sm2dn-normal-alg", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedVerify_02(String dn, String alg) {
        System.out.println("Detached验签(detachedVerify),参数均正常,SM2证书");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.detachedSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.detachedVerify(pOrgData, signresult);
            if (!"SHA1".equals(alg) && !"SHA256".equals(alg)) {
                if (verify.getBoolResult() != true || verify.getReturnCode() != 0
                        || !"success".equals(verify.getReturnContent())) {
                    Assert.fail(" 金E卫ABCJEW-detached验签，测试SM2证书，SM3摘要算法，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
                }
            }
            else {
                if (verify.getReturnCode() != 0) {
                    if (verify.getReturnCode() != -100129) {
                        Assert.fail(" 金E卫ABCJEW-detached验签，测试SM2证书，SHA1或SHA256摘要算法，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
                    }
                    Reporter.log("金E卫ABCJEW-detached验签，测试SM2证书，SHA1或SHA256摘要算法不支持");
                }
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-detached验签，测试SM2证书，抛异常！" + e.getMessage());
        }
    }

    /**
     * Detached验签，签名值被篡改
     */
    @Test(groups = "abcjew.detachedverify.normal", dataProvider = "normal-alg-dn", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedVerify_03(String alg, String dn) {
        System.out.println("Detached验签(detachedVerify),签名值被篡改");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.detachedSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            // 修改签名结果
            StringBuilder sb = new StringBuilder(signresult);
            sb.replace(signresult.length() - 5, signresult.length() - 2, "BCD");
            String new_sign_result;
            new_sign_result = sb.toString();
            verify = agent.detachedVerify( pOrgData, new_sign_result);
            if (verify.getBoolResult() != false || verify.getReturnCode() != -100104) {
                Assert.fail(" 金E卫ABCJEW-attached验签，测试被篡改的签名值，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-attached验签，测试被篡改的签名值，抛异常！" + e.getMessage());
        }
    }

    /**
     * Detached验签，签名值为空或者null
     */
    @Test(groups = "abcjew.detachedverify.normal", dataProvider = "emptys-parameter", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedVerify_04(String sign) {
        System.out.println("Detached验签(detachedVerify),签名值为空或者null");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult verify;
            verify = agent.detachedVerify( pOrgData, sign);
            if (verify.getReturnCode() != -1011) {
                if (verify.getReturnCode() != -100100) {
                    Assert.fail(" 金E卫ABCJEW-detached验签，测试签名值为空或者null，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-detached验签，测试签名值为空或者null，抛异常！" + e.getMessage());
        }
    }

    /**
     * Detached验签，过期证书
     */
    @Test(groups = "abcjew.detachedverify.normal", dataProvider = "expire-alg-dn", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedVerify_05(String alg, String dn) {
        System.out.println("Detached验签(detachedVerify),证书过期");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.detachedSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.detachedVerify(pOrgData,signresult);
            if (verify.getBoolResult() != false || verify.getReturnCode() != -100106) {
                Assert.fail(" 金E卫ABCJEW-detached验签，测试过期证书，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-detached验签，测试过期证书，抛异常！" + e.getMessage());
        }
    }

    /**
     * Detached验签，作废证书
     */
    @Test(groups = "abcjew.detachedverify.normal", dataProvider = "revoke-alg-dn", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedVerify_06(String alg, String dn) {
        System.out.println("Detached验签(detachedVerify),证书作废");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.detachedSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            if (!("C=CN,O=infosec,OU=test3,CN=C020revokeMatchingAnyCrlfbd").equals(dn)
                    && !("C=CN,O=infosec,CN=C020revokedNocrlfile").equals(dn)) {
                verify = agent.detachedVerify( pOrgData, signresult);
                if (verify.getBoolResult() != false || verify.getReturnCode() != -100108) {
                    Assert.fail(" 金E卫ABCJEW-detached验签，测试作废证书，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-detached验签，测试作废证书，抛异常！" + e.getMessage());
        }
    }

    /**
     * Detached验签，不受信任证书
     */
    @Test(groups = "abcjew.detachedverify.normal", dataProvider = "nottrust-alg-dn", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedVerify_07(String alg, String dn) {
        System.out.println("Detached验签(detachedVerify),证书不受信任");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.detachedSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.detachedVerify(pOrgData, signresult);
            if (verify.getBoolResult() != false || verify.getReturnCode() != -100124) {
                Assert.fail(" 金E卫ABCJEW-detached验签，测试不受信任证书，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-detached验签，测试不受信任证书，抛异常！" + e.getMessage());
        }
    }

    /**
     * Detached验签，服务器不存在公钥证书，仍应验签成功
     */
    @Test(groups = "abcjew.detachedverify.normal")
    public void testdetachedVerify_08() {
        System.out.println("Detached验签(detachedVerify),服务器不存在公钥证书仍应验签成功");
        try {
            UpkiResult verify;
            String signresult = "MIIFeAYJKoZIhvcNAQcCoIIFaTCCBWUCAQExDzANBglghkgBZQMEAgEFADALBgkqhkiG9w0BBwGgggO9MIIDuTCCAqGgAwIBAgIFO1OkHnUwDQYJKoZIhvcNAQELBQAwSzELMAkGA1UEBhMCY24xJjAkBgNVBAoMHUlORk9TRUMgVGVjaG5vbG9naWVzIFNIQTI1NklEMRQwEgYDVQQDDAthcHBTSEEyNTZJRDAeFw0xNzExMjEwMjU3MDdaFw0yNjA4MTIwMjQ3MTRaMCwxCzAJBgNVBAYTAkNOMQswCQYDVQQKDAJRQTEQMA4GA1UEAwwHQ1NfMjA0ODCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMNoA9fcSXJyB5qRoa4ihJVL3MLXgQbreUL7KW4iiSwMPvn+dNVSU6VQ7iOqe+B8FcYcou2cnoBJEngnXh4ahVUlPyUHArkhOC/M7+2CKo/U3uJt7XdCv+NecSREAWZO2rRO2npkEKSD9ekmqFkx/QMIjA55RM628Nfq5hjmR1BMEdMxFW1TAzIqA/5xGaMENPV8v9TXv39wwlnbxN+WujOQ3Y4asObWmAn+UVIEu6RcXKw2j8+13svFgL1b89CXzhPSUZp/3TcAFXxqKY/mRr6uJEcrIEPHoPhVc1pO62PqPLfoNxnI88VoNZsVT6gfE3mvZmaJVjwmsbvYzJFoMiUCAwEAAaOBwjCBvzAfBgNVHSMEGDAWgBR+2NS35iQoLVNxo+cuS6rAo9y7GDAJBgNVHRMEAjAAMGUGA1UdHwReMFwwWqBYoFakVDBSMQ0wCwYDVQQDDARjcmw1MQwwCgYDVQQLDANjcmwxJjAkBgNVBAoMHUlORk9TRUMgVGVjaG5vbG9naWVzIFNIQTI1NklEMQswCQYDVQQGEwJjbjALBgNVHQ8EBAMCB4AwHQYDVR0OBBYEFKsJRzbUvBL7+Z7oN06vgdQYk75mMA0GCSqGSIb3DQEBCwUAA4IBAQAtyW8Kkh7ScvyZP7YR+Ma48rfJiE7/5o4h9QAfmTwc2RNbyH1VGKDR6vcOKa4PF3+8XPv2QZOOmRnr0sm15H4XCzp4mOy7seiZyzLGS7/7+iBRE1WVMHa5dkbxGN/R9p0EKPD6ZFbgcJtKhcOCzi3ZTDn9ubLPy803QgUJfkuMKVxdQ4ZdD6iBUQTuuwARATJ8Pc5fYQX9quiUUnWj2Pi7f8zkNRVlFrOd2Uu1s45yfXJ3i4WrOG3NGbEzLDBpDMcd36qf+Z95KysUadlvtWA+djnK3UrG3HZ8HmWCQ4mOgHMz4UisCo6DjW+jo2VnC70e8OG1rjVLvXXmr4mmUD1nMYIBfzCCAXsCAQEwVDBLMQswCQYDVQQGEwJjbjEmMCQGA1UECgwdSU5GT1NFQyBUZWNobm9sb2dpZXMgU0hBMjU2SUQxFDASBgNVBAMMC2FwcFNIQTI1NklEAgU7U6QedTANBglghkgBZQMEAgEFADANBgkqhkiG9w0BAQEFAASCAQC49ZbN6su7XPlYDYKPyyJ7wNWXM90+sM9amQWx5WvisKMyzyXzbRJDAGR5o0g1Rs5SJQapp6B3ISBo7rfNPncKetIdNsAL4S1OELyWp2o6eVd9Qe3Tgtq/fnSJCuLrDwEmPj9obzXSTnzxJ4+WqNNCdnuUFKAaMry0kf8/FUqOYqjclKS8xLDuEykKUKJJhcAHuihfYNN+3du/QVSPMx4DH1Px1yxbDIpLTA0iqd/EqWV54iAjQbbmqRHVzbcUtQ5TdJD9qAB1QDaJT2hmb0rtp2gnTjyybp3KBfkGGCU9bdkEWLIGvWJGzVtgkXhzYJ1LygqKpM7g5iHhI0eH7skM";
            verify = agent.detachedVerify("asd".getBytes(), signresult);
            if (verify.getBoolResult() != true || verify.getReturnCode() != 0
                    || !"success".equals(verify.getReturnContent())) {
                Assert.fail(" 金E卫ABCJEW-detached验签，测试服务器不存在公钥证书是否验签成功，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-detached验签，测试服务器不存在公钥证书是否验签成功，抛异常！" + e.getMessage());
        }
    }

    /**
     * Dettached验签，密钥传RSA证书SN的签名值
     */
    @Test(groups = "abcjew.detachedverify.normal", dataProvider = "normal-rsa-sn-dalg", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedVerify_09(String sn, String alg) {
        System.out.println("Detached验签(detachedVerify),密钥传RSA证书SN的签名值");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.detachedSign(pOrgData, sn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.detachedVerify(pOrgData, signresult);
            if (verify.getBoolResult() != true || verify.getReturnCode() != 0
                    || !"success".equals(verify.getReturnContent())) {
                Assert.fail(" 金E卫ABCJEW-detached验签，测试RSA密钥证书传SN的签名值，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-detached验签，测试RSA密钥证书传SN的签名值，抛异常！" + e.getMessage());
        }
    }


    /**
     * Detached验签，密钥传SM2证书SN的签名值
     */
    @Test(groups = "abcjew.detachedverify.normal", dataProvider = "normal-sm2-sn-dalg", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedVerify_10(String sn, String alg) {
        System.out.println("Detached验签(detachedVerify),密钥传SM2证书SN的签名值");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.detachedSign(pOrgData, sn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            if (!"SHA1".equals(alg) && !"SHA256".equals(alg)) {
                verify = agent.detachedVerify(pOrgData, signresult);
                if (verify.getBoolResult() != true || verify.getReturnCode() != 0
                        || !"success".equals(verify.getReturnContent())) {
                    Assert.fail(" 金E卫ABCJEW-detached验签，测试SM2密钥证书传SN的签名值，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-detached验签，测试SM2密钥证书传SN的签名值，抛异常！" + e.getMessage());
        }
    }

    /**
     * Detached验签，使用默认摘要算法的签名值
     */
    @Test(groups = "abcjew.detachedverify.normal", dataProvider = "normal-dn", dataProviderClass = NetSignDataProvider.class)
    public void  testdetachedVerify_11(String dn) {
        System.out.println("Detached验签(detachedVerify),使用默认摘要算法的签名值");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.detachedSign(pOrgData, dn, null);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.detachedVerify(pOrgData,signresult);
            if (verify.getBoolResult() != true || verify.getReturnCode() != 0
                    || !"success".equals(verify.getReturnContent())) {
                Assert.fail(" 金E卫ABCJEW-detached验签，测试默认摘要算法的签名值，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-detached验签，测试默认摘要算法的签名值，抛异常！" + e.getMessage());
        }
    }

    /**
     * Detached验签，RSA证书Alg小写的签名值
     */
    @Test(groups = "abcjew.detachedverify.normal", dataProvider = "rsadn-normal-alg", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedVerify_12(String dn, String alg) {
        System.out.println("Detached验签(detachedVerify),RSA证书小写摘要算法的签名值");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            String littlealg = alg.toLowerCase();
            sign = agent.detachedSign(pOrgData, dn, littlealg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.detachedVerify(pOrgData,signresult);
            if (verify.getBoolResult() != true || verify.getReturnCode() != 0
                    || !"success".equals(verify.getReturnContent())) {
                Assert.fail(" 金E卫ABCJEW-detached验签，测试RSA类型小写摘要算法的签名值，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-detached验签，测试RSA类型小写摘要算法的签名值，抛异常！" + e.getMessage());
        }
    }

    /**
     * Detached验签，SM2证书Alg小写的签名值
     */
    @Test(groups = "abcjew.detachedverify.normal", dataProvider = "sm2dn-normal-alg", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedVerify_13(String dn, String alg) {
        System.out.println("Detached验签(detachedVerify),SM2证书小写摘要算法的签名值");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            String littlealg = alg.toLowerCase();
            sign = agent.detachedSign(pOrgData, dn, littlealg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();

            if (!"SHA1".equals(alg) && !"SHA256".equals(alg)) {
                verify = agent.detachedVerify(pOrgData,signresult);
                if (verify.getBoolResult() != true || verify.getReturnCode() != 0
                        || !"success".equals(verify.getReturnContent())) {
                    Assert.fail(" 金E卫ABCJEW-detached验签，测试SM2证书，小写摘要算法，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-detached验签，测试SM2证书，小写摘要算法的签名值，抛异常！" + e.getMessage());
        }
    }

    /**
     * Detached验签，原文不一致
     */
    @Test(groups = "abcjew.detachedverify.normal", dataProvider = "normal-alg-dn", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedVerify_14(String alg, String dn) {
        System.out.println("Detached验签(detachedVerify),原文不一致");
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.detachedSign("aaa".getBytes(), dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();

            verify = agent.detachedVerify("basdd".getBytes(), signresult);
            if (verify.getReturnCode() != -100104) {
                Assert.fail(" 金E卫ABCJEW-detached验签，测试原文不一致，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-detached验签，测试原文不一致，抛异常！" + e.getMessage());
        }
    }

    /**
     * Detached验签，原文为null
     */
    @Test(groups = "abcjew.detachedverify.normal", dataProvider = "normal-alg-dn", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedVerify_15(String alg, String dn) {
        System.out.println("Detached验签(detachedVerify),原文为null");
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.detachedSign("asd".getBytes(), dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();

            verify = agent.detachedVerify(null, signresult);
            if (verify.getReturnCode() != -100208) {
                Assert.fail(" 金E卫ABCJEW-Detached验签，测试原文为null，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-Detached验签，测试原文为null，抛异常！" + e.getMessage());
        }
    }

    /**
     * Detached验签，原文为空
     */
    @Test(groups = "abcjew.detachedverify.normal", dataProvider = "normal-alg-dn", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedVerify_16(String alg, String dn) {
        System.out.println("Detached验签(detachedVerify),原文为空");
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.detachedSign("asd".getBytes(), dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();

            verify = agent.detachedVerify("".getBytes(), signresult);
            if (verify.getReturnCode() != -100104) {
                Assert.fail(" 金E卫ABCJEW-Detached验签，测试原文为空，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-Detached验签，测试原文为空，抛异常！" + e.getMessage());
        }
    }

}
