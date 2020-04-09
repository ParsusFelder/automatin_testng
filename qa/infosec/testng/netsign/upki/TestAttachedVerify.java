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

import java.util.Map;

/**
 * @author suiyixin
 * @ClassName: TestAttachedVerify
 * @date 2020-03-09 15:03
 * @Description: <p>用例覆盖点：</p>
 * <p>1）所有传参均正常</p>
 * <p>2）签名值被篡改</p>
 * <p>3）签名值为空或者null</p>
 * <p>4）签名证书已过期</p>
 * <p>5）签名证书已作废</p>
 * <p>6）签名证书不受信任</p>
 * <p>7）验签证书不存在</p>
 * <p>8）密钥传sn的签名值</p>
 * <p>9）大原文的签名值,RSA证书</p>
 * <p>10）大原文的签名值,SM2证书</p>
 * <p>11）使用默认摘要算法的签名值</p>
 * <p>12）使用小写摘要算法的签名值</p>
 */
public class TestAttachedVerify {
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
     * Attached验签，所有传参均正常
     */
    @Test(groups = "abcjew.attachedverify.normal", dataProvider = "normal-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testattachedVerify_01(String alg, String dn) {
        System.out.println("Attached验签(attachedVerify),传参均正确");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.attachedSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.attachedVerify(signresult);
            if (verify.getBoolResult() != true || verify.getReturnCode() != 0
                    || !"success".equals(verify.getReturnContent())) {
                Assert.fail(" 金E卫ABCJEW-attached验签，测试所有传参均正常，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-attached验签，测试所有传参均正常，抛异常！" + e.getMessage());
        }
    }

    /**
     * Attached验签，签名值被篡改
     */
    @Test(groups = "abcjew.attachedverify.normal", dataProvider = "normal-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testattachedVerify_02(String alg, String dn) {
        System.out.println("Attached验签(attachedVerify),签名值被篡改");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.attachedSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            // 修改签名结果
            StringBuilder sb = new StringBuilder(signresult);
            sb.replace(signresult.length() - 5, signresult.length() - 2, "BCD");
            String new_sign_result;
            new_sign_result = sb.toString();
            verify = agent.attachedVerify(new_sign_result);
            if (verify.getBoolResult() != false || verify.getReturnCode() != -100104) {
                Assert.fail(" 金E卫ABCJEW-attached验签，测试被篡改的签名值，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-attached验签，测试被篡改的签名值，抛异常！" + e.getMessage());
        }
    }

    /**
     * Attached验签，签名值为空或者null
     */
    @Test(groups = "abcjew.attachedverify.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testattachedVerify_03(String sign) {
        System.out.println("Attached验签(attachedVerify),签名值为空或者null");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult verify;
            verify = agent.attachedVerify(sign);
            if (verify.getReturnCode() != -1011) {
                if (verify.getReturnCode() != -1) {
                    Assert.fail(" 金E卫ABCJEW-attached验签，测试签名值为空或者null，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-attached验签，测试签名值为空或者null，抛异常！" + e.getMessage());
        }
    }

    /**
     * Attached验签，过期证书
     */
    @Test(groups = "abcjew.attachedverify.normal", dataProvider = "expire-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testattachedVerify_04(String alg, String dn) {
        System.out.println("Attached验签(attachedVerify),证书过期");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.attachedSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.attachedVerify(signresult);
            if (verify.getBoolResult() != false || verify.getReturnCode() != -100106) {
                Assert.fail(" 金E卫ABCJEW-attached验签，测试过期证书，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-attached验签，测试过期证书，抛异常！" + e.getMessage());
        }
    }

    /**
     * Attached验签，作废证书
     */
    @Test(groups = "abcjew.attachedverify.normal", dataProvider = "revoke-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testattachedVerify_05(String alg, String dn) {
        System.out.println("Attached验签(attachedVerify),证书作废");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.attachedSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            if (!("C=CN,O=infosec,OU=test3,CN=C020revokeMatchingAnyCrlfbd").equals(dn)
                    && !("C=CN,O=infosec,CN=C020revokedNocrlfile").equals(dn)) {
                verify = agent.attachedVerify(signresult);
                if (verify.getBoolResult() != false || verify.getReturnCode() != -100108) {
                    Assert.fail(" 金E卫ABCJEW-attached验签，测试作废证书，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-attached验签，测试作废证书，抛异常！" + e.getMessage());
        }
    }

    /**
     * Attached验签，不受信任证书
     */
    @Test(groups = "abcjew.attachedverify.normal", dataProvider = "nottrust-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testattachedVerify_06(String alg, String dn) {
        System.out.println("Attached验签(attachedVerify),证书不受信任");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.attachedSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.attachedVerify(signresult);
            if (verify.getBoolResult() != false || verify.getReturnCode() != -100124) {
                Assert.fail(" 金E卫ABCJEW-attached验签，测试不受信任证书，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-attached验签，测试不受信任证书，抛异常！" + e.getMessage());
        }
    }

    /**
     * Attached验签，服务器不存在公钥证书，仍应验签成功
     */
    @Test(groups = "abcjew.attachedverify.normal")
    public void testattachedVerify_07() {
        System.out.println("Attached验签(attachedVerify),服务器不存在公钥证书，仍应验签成功");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult verify;
            String signresult =
                    "MIIFfwYJKoZIhvcNAQcCoIIFcDCCBWwCAQExDzANBglghkgBZQMEAgEFADASBgkqhkiG9w0BBwGgBQQDYXNkoIIDvTCCA7kwggKhoAMCAQICBTtTpB51MA0GCSqGSIb3DQEBCwUAMEsxCzAJBgNVBAYTAmNuMSYwJAYDVQQKDB1JTkZPU0VDIFRlY2hub2xvZ2llcyBTSEEyNTZJRDEUMBIGA1UEAwwLYXBwU0hBMjU2SUQwHhcNMTcxMTIxMDI1NzA3WhcNMjYwODEyMDI0NzE0WjAsMQswCQYDVQQGEwJDTjELMAkGA1UECgwCUUExEDAOBgNVBAMMB0NTXzIwNDgwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDDaAPX3ElycgeakaGuIoSVS9zC14EG63lC+yluIoksDD75/nTVUlOlUO4jqnvgfBXGHKLtnJ6ASRJ4J14eGoVVJT8lBwK5ITgvzO/tgiqP1N7ibe13Qr/jXnEkRAFmTtq0Ttp6ZBCkg/XpJqhZMf0DCIwOeUTOtvDX6uYY5kdQTBHTMRVtUwMyKgP+cRmjBDT1fL/U179/cMJZ28TflrozkN2OGrDm1pgJ/lFSBLukXFysNo/Ptd7LxYC9W/PQl84T0lGaf903ABV8aimP5ka+riRHKyBDx6D4VXNaTutj6jy36DcZyPPFaDWbFU+oHxN5r2ZmiVY8JrG72MyRaDIlAgMBAAGjgcIwgb8wHwYDVR0jBBgwFoAUftjUt+YkKC1TcaPnLkuqwKPcuxgwCQYDVR0TBAIwADBlBgNVHR8EXjBcMFqgWKBWpFQwUjENMAsGA1UEAwwEY3JsNTEMMAoGA1UECwwDY3JsMSYwJAYDVQQKDB1JTkZPU0VDIFRlY2hub2xvZ2llcyBTSEEyNTZJRDELMAkGA1UEBhMCY24wCwYDVR0PBAQDAgeAMB0GA1UdDgQWBBSrCUc21LwS+/me6DdOr4HUGJO+ZjANBgkqhkiG9w0BAQsFAAOCAQEALclvCpIe0nL8mT+2EfjGuPK3yYhO/+aOIfUAH5k8HNkTW8h9VRig0er3DimuDxd/vFz79kGTjpkZ69LJteR+Fws6eJjsu7Homcsyxku/+/ogURNVlTB2uXZG8Rjf0fadBCjw+mRW4HCbSoXDgs4t2Uw5/bmyz8vNN0IFCX5LjClcXUOGXQ+ogVEE7rsAEQEyfD3OX2EF/arolFJ1o9j4u3/M5DUVZRazndlLtbOOcn1yd4uFqzhtzRmxMywwaQzHHd+qn/mfeSsrFGnZb7VgPnY5yt1Kxtx2fB5lgkOJjoBzM+FIrAqOg41vo6NlZwu9HvDhta41S7115q+JplA9ZzGCAX8wggF7AgEBMFQwSzELMAkGA1UEBhMCY24xJjAkBgNVBAoMHUlORk9TRUMgVGVjaG5vbG9naWVzIFNIQTI1NklEMRQwEgYDVQQDDAthcHBTSEEyNTZJRAIFO1OkHnUwDQYJYIZIAWUDBAIBBQAwDQYJKoZIhvcNAQEBBQAEggEAuPWWzerLu1z5WA2Cj8sie8DVlzPdPrDPWpkFseVr4rCjMs8l820SQwBkeaNINUbOUiUGqaegdyEgaO63zT53CnrSHTbAC+EtThC8lqdqOnlXfUHt04Lav350iQri6w8BJj4/aG810k588SePlqjTQnZ7lBSgGjK8tJH/PxVKjmKo3JSkvMSw7hMpClCiSYXAB7ooX2DTft3bv0FUjzMeAx9T8dcsWwyKS0wNIqnfxKlleeIgI0G25qkR1c23FLUOU3SQ/agAdUA2iU9oZm9K7adoJ048sm6dygX5BhglPW3ZBFiyBr1iRs1bYJF4c2CdS8oKiqTO4OYh4SNHh+7JDA==";
            verify = agent.attachedVerify(signresult);
            if (verify.getBoolResult() != true || verify.getReturnCode() != 0
                    || !"success".equals(verify.getReturnContent())) {
                Assert.fail(" 金E卫ABCJEW-attached验签，测试服务器不存在公钥证书是否验签成功，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-attached验签，测试服务器不存在公钥证书是否验签成功，抛异常！" + e.getMessage());
        }
    }

    /**
     * Attached验签，密钥传证书SN的签名值
     */
    @Test(groups = "abcjew.attachedverify.normal", dataProvider = "normal-alg-sn", dataProviderClass =
            NetSignDataProvider.class)
    public void testattachedVerify_08(String alg, String sn) {
        System.out.println("Attached验签(attachedVerify),密钥传证书SN的签名值");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.attachedSign(pOrgData, sn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.attachedVerify(signresult);
            if (verify.getBoolResult() != true || verify.getReturnCode() != 0
                    || !"success".equals(verify.getReturnContent())) {
                Assert.fail(" 金E卫ABCJEW-attached验签，测试密钥证书传SN的签名值，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-attached验签，测试密钥证书传SN的签名值，抛异常！" + e.getMessage());
        }
    }

    /**
     * Attached验签，大原文的签名值，RSA证书
     */
    @Test(groups = "abcjew.attachedverify.normal")
    public void testattachedVerify_09() {
        System.out.println("Attached验签(attachedVerify),大原文的签名值,RSA证书");
        byte[] pOrgData = ParseFile.getFileData(ParameterUtil.bigfilepath);
        try {
            UpkiResult sign;
            UpkiResult verify;
            String alg = "SHA1";
            String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
            sign = agent.attachedSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.attachedVerify(signresult);
            if (verify.getBoolResult() != true || verify.getReturnCode() != 0
                    || !"success".equals(verify.getReturnContent())) {
                Assert.fail(" 金E卫ABCJEW-attached验签，测试大原文，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-attached验签，测试大原文，抛异常！" + e.getMessage());
        }
    }

    /**
     * Attached验签，大原文的签名值，SM2证书
     */
    @Test(groups = "abcjew.attachedverify.normal")
    public void testattachedVerify_10() {
        System.out.println("Attached验签(attachedVerify),大原文的签名值,SM2证书");
        byte[] pOrgData = ParseFile.getFileData(ParameterUtil.bigfilepath);
        try {
            UpkiResult sign;
            UpkiResult verify;
            String alg = "SM3";
            String dn = "C=cn,O=INFOSEC Technologies RSA,CN=SS019normal";
            sign = agent.attachedSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.attachedVerify(signresult);
            if (verify.getBoolResult() != true || verify.getReturnCode() != 0
                    || !"success".equals(verify.getReturnContent())) {
                Assert.fail(" 金E卫ABCJEW-attached验签，测试大原文，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-attached验签，测试大原文，抛异常！" + e.getMessage());
        }
    }

    /**
     * Attached验签，使用默认摘要算法的签名值
     */
    @Test(groups = "abcjew.attachedverify.normal", dataProvider = "normal-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testattachedVerify_11(String dn) {
        System.out.println("Attached验签(attachedVerify),使用默认摘要算法的签名值");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.attachedSign(pOrgData, dn, null);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.attachedVerify(signresult);
            if (verify.getBoolResult() != true || verify.getReturnCode() != 0
                    || !"success".equals(verify.getReturnContent())) {
                Assert.fail(" 金E卫ABCJEW-attached验签，测试默认摘要算法的签名值，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-attached验签，测试默认摘要算法的签名值，抛异常！" + e.getMessage());
        }
    }

    /**
     * Attached验签，Alg小写的签名值
     */
    @Test(groups = "abcjew.attachedverify.normal", dataProvider = "normal-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testattachedVerify_12(String alg, String dn) {
        System.out.println("Attached验签(attachedVerify),使用小写摘要算法的签名值");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            String littlealg = alg.toLowerCase();
            sign = agent.attachedSign(pOrgData, dn, littlealg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.attachedVerify(signresult);
            if (verify.getBoolResult() != true || verify.getReturnCode() != 0
                    || !"success".equals(verify.getReturnContent())) {
                Assert.fail(" 金E卫ABCJEW-attached验签，测试小写摘要算法的签名值，失败！" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" 金E卫ABCJEW-attached验签，测试小写摘要算法的签名值，抛异常！" + e.getMessage());
        }
    }
}
