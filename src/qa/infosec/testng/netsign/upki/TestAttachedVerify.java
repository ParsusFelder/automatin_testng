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
 * @Description: <p>�������ǵ㣺</p>
 * <p>1�����д��ξ�����</p>
 * <p>2��ǩ��ֵ���۸�</p>
 * <p>3��ǩ��ֵΪ�ջ���null</p>
 * <p>4��ǩ��֤���ѹ���</p>
 * <p>5��ǩ��֤��������</p>
 * <p>6��ǩ��֤�鲻������</p>
 * <p>7����ǩ֤�鲻����</p>
 * <p>8����Կ��sn��ǩ��ֵ</p>
 * <p>9����ԭ�ĵ�ǩ��ֵ,RSA֤��</p>
 * <p>10����ԭ�ĵ�ǩ��ֵ,SM2֤��</p>
 * <p>11��ʹ��Ĭ��ժҪ�㷨��ǩ��ֵ</p>
 * <p>12��ʹ��СдժҪ�㷨��ǩ��ֵ</p>
 */
public class TestAttachedVerify {
    static String ip, port, password;
    static String host, sftp_port, sftp_password, sftp_user;

    NetSignServerInit init = new NetSignServerInit();
    UpkiAgent agent;
    SFTPFile tmp = new SFTPFile();

    {
        // ����netsignconfig.properties�����ļ�����ȡ������Ϣ,confpath=null ʹ��Ĭ��·��
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
     * Attached��ǩ�����д��ξ�����
     */
    @Test(groups = "abcjew.attachedverify.normal", dataProvider = "normal-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testattachedVerify_01(String alg, String dn) {
        System.out.println("Attached��ǩ(attachedVerify),���ξ���ȷ");
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
                Assert.fail(" ��E��ABCJEW-attached��ǩ���������д��ξ�������ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-attached��ǩ���������д��ξ����������쳣��" + e.getMessage());
        }
    }

    /**
     * Attached��ǩ��ǩ��ֵ���۸�
     */
    @Test(groups = "abcjew.attachedverify.normal", dataProvider = "normal-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testattachedVerify_02(String alg, String dn) {
        System.out.println("Attached��ǩ(attachedVerify),ǩ��ֵ���۸�");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.attachedSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            // �޸�ǩ�����
            StringBuilder sb = new StringBuilder(signresult);
            sb.replace(signresult.length() - 5, signresult.length() - 2, "BCD");
            String new_sign_result;
            new_sign_result = sb.toString();
            verify = agent.attachedVerify(new_sign_result);
            if (verify.getBoolResult() != false || verify.getReturnCode() != -100104) {
                Assert.fail(" ��E��ABCJEW-attached��ǩ�����Ա��۸ĵ�ǩ��ֵ��ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-attached��ǩ�����Ա��۸ĵ�ǩ��ֵ�����쳣��" + e.getMessage());
        }
    }

    /**
     * Attached��ǩ��ǩ��ֵΪ�ջ���null
     */
    @Test(groups = "abcjew.attachedverify.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testattachedVerify_03(String sign) {
        System.out.println("Attached��ǩ(attachedVerify),ǩ��ֵΪ�ջ���null");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult verify;
            verify = agent.attachedVerify(sign);
            if (verify.getReturnCode() != -1011) {
                if (verify.getReturnCode() != -1) {
                    Assert.fail(" ��E��ABCJEW-attached��ǩ������ǩ��ֵΪ�ջ���null��ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-attached��ǩ������ǩ��ֵΪ�ջ���null�����쳣��" + e.getMessage());
        }
    }

    /**
     * Attached��ǩ������֤��
     */
    @Test(groups = "abcjew.attachedverify.normal", dataProvider = "expire-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testattachedVerify_04(String alg, String dn) {
        System.out.println("Attached��ǩ(attachedVerify),֤�����");
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
                Assert.fail(" ��E��ABCJEW-attached��ǩ�����Թ���֤�飬ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-attached��ǩ�����Թ���֤�飬���쳣��" + e.getMessage());
        }
    }

    /**
     * Attached��ǩ������֤��
     */
    @Test(groups = "abcjew.attachedverify.normal", dataProvider = "revoke-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testattachedVerify_05(String alg, String dn) {
        System.out.println("Attached��ǩ(attachedVerify),֤������");
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
                    Assert.fail(" ��E��ABCJEW-attached��ǩ����������֤�飬ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-attached��ǩ����������֤�飬���쳣��" + e.getMessage());
        }
    }

    /**
     * Attached��ǩ����������֤��
     */
    @Test(groups = "abcjew.attachedverify.normal", dataProvider = "nottrust-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testattachedVerify_06(String alg, String dn) {
        System.out.println("Attached��ǩ(attachedVerify),֤�鲻������");
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
                Assert.fail(" ��E��ABCJEW-attached��ǩ�����Բ�������֤�飬ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-attached��ǩ�����Բ�������֤�飬���쳣��" + e.getMessage());
        }
    }

    /**
     * Attached��ǩ�������������ڹ�Կ֤�飬��Ӧ��ǩ�ɹ�
     */
    @Test(groups = "abcjew.attachedverify.normal")
    public void testattachedVerify_07() {
        System.out.println("Attached��ǩ(attachedVerify),�����������ڹ�Կ֤�飬��Ӧ��ǩ�ɹ�");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult verify;
            String signresult =
                    "MIIFfwYJKoZIhvcNAQcCoIIFcDCCBWwCAQExDzANBglghkgBZQMEAgEFADASBgkqhkiG9w0BBwGgBQQDYXNkoIIDvTCCA7kwggKhoAMCAQICBTtTpB51MA0GCSqGSIb3DQEBCwUAMEsxCzAJBgNVBAYTAmNuMSYwJAYDVQQKDB1JTkZPU0VDIFRlY2hub2xvZ2llcyBTSEEyNTZJRDEUMBIGA1UEAwwLYXBwU0hBMjU2SUQwHhcNMTcxMTIxMDI1NzA3WhcNMjYwODEyMDI0NzE0WjAsMQswCQYDVQQGEwJDTjELMAkGA1UECgwCUUExEDAOBgNVBAMMB0NTXzIwNDgwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDDaAPX3ElycgeakaGuIoSVS9zC14EG63lC+yluIoksDD75/nTVUlOlUO4jqnvgfBXGHKLtnJ6ASRJ4J14eGoVVJT8lBwK5ITgvzO/tgiqP1N7ibe13Qr/jXnEkRAFmTtq0Ttp6ZBCkg/XpJqhZMf0DCIwOeUTOtvDX6uYY5kdQTBHTMRVtUwMyKgP+cRmjBDT1fL/U179/cMJZ28TflrozkN2OGrDm1pgJ/lFSBLukXFysNo/Ptd7LxYC9W/PQl84T0lGaf903ABV8aimP5ka+riRHKyBDx6D4VXNaTutj6jy36DcZyPPFaDWbFU+oHxN5r2ZmiVY8JrG72MyRaDIlAgMBAAGjgcIwgb8wHwYDVR0jBBgwFoAUftjUt+YkKC1TcaPnLkuqwKPcuxgwCQYDVR0TBAIwADBlBgNVHR8EXjBcMFqgWKBWpFQwUjENMAsGA1UEAwwEY3JsNTEMMAoGA1UECwwDY3JsMSYwJAYDVQQKDB1JTkZPU0VDIFRlY2hub2xvZ2llcyBTSEEyNTZJRDELMAkGA1UEBhMCY24wCwYDVR0PBAQDAgeAMB0GA1UdDgQWBBSrCUc21LwS+/me6DdOr4HUGJO+ZjANBgkqhkiG9w0BAQsFAAOCAQEALclvCpIe0nL8mT+2EfjGuPK3yYhO/+aOIfUAH5k8HNkTW8h9VRig0er3DimuDxd/vFz79kGTjpkZ69LJteR+Fws6eJjsu7Homcsyxku/+/ogURNVlTB2uXZG8Rjf0fadBCjw+mRW4HCbSoXDgs4t2Uw5/bmyz8vNN0IFCX5LjClcXUOGXQ+ogVEE7rsAEQEyfD3OX2EF/arolFJ1o9j4u3/M5DUVZRazndlLtbOOcn1yd4uFqzhtzRmxMywwaQzHHd+qn/mfeSsrFGnZb7VgPnY5yt1Kxtx2fB5lgkOJjoBzM+FIrAqOg41vo6NlZwu9HvDhta41S7115q+JplA9ZzGCAX8wggF7AgEBMFQwSzELMAkGA1UEBhMCY24xJjAkBgNVBAoMHUlORk9TRUMgVGVjaG5vbG9naWVzIFNIQTI1NklEMRQwEgYDVQQDDAthcHBTSEEyNTZJRAIFO1OkHnUwDQYJYIZIAWUDBAIBBQAwDQYJKoZIhvcNAQEBBQAEggEAuPWWzerLu1z5WA2Cj8sie8DVlzPdPrDPWpkFseVr4rCjMs8l820SQwBkeaNINUbOUiUGqaegdyEgaO63zT53CnrSHTbAC+EtThC8lqdqOnlXfUHt04Lav350iQri6w8BJj4/aG810k588SePlqjTQnZ7lBSgGjK8tJH/PxVKjmKo3JSkvMSw7hMpClCiSYXAB7ooX2DTft3bv0FUjzMeAx9T8dcsWwyKS0wNIqnfxKlleeIgI0G25qkR1c23FLUOU3SQ/agAdUA2iU9oZm9K7adoJ048sm6dygX5BhglPW3ZBFiyBr1iRs1bYJF4c2CdS8oKiqTO4OYh4SNHh+7JDA==";
            verify = agent.attachedVerify(signresult);
            if (verify.getBoolResult() != true || verify.getReturnCode() != 0
                    || !"success".equals(verify.getReturnContent())) {
                Assert.fail(" ��E��ABCJEW-attached��ǩ�����Է����������ڹ�Կ֤���Ƿ���ǩ�ɹ���ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-attached��ǩ�����Է����������ڹ�Կ֤���Ƿ���ǩ�ɹ������쳣��" + e.getMessage());
        }
    }

    /**
     * Attached��ǩ����Կ��֤��SN��ǩ��ֵ
     */
    @Test(groups = "abcjew.attachedverify.normal", dataProvider = "normal-alg-sn", dataProviderClass =
            NetSignDataProvider.class)
    public void testattachedVerify_08(String alg, String sn) {
        System.out.println("Attached��ǩ(attachedVerify),��Կ��֤��SN��ǩ��ֵ");
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
                Assert.fail(" ��E��ABCJEW-attached��ǩ��������Կ֤�鴫SN��ǩ��ֵ��ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-attached��ǩ��������Կ֤�鴫SN��ǩ��ֵ�����쳣��" + e.getMessage());
        }
    }

    /**
     * Attached��ǩ����ԭ�ĵ�ǩ��ֵ��RSA֤��
     */
    @Test(groups = "abcjew.attachedverify.normal")
    public void testattachedVerify_09() {
        System.out.println("Attached��ǩ(attachedVerify),��ԭ�ĵ�ǩ��ֵ,RSA֤��");
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
                Assert.fail(" ��E��ABCJEW-attached��ǩ�����Դ�ԭ�ģ�ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-attached��ǩ�����Դ�ԭ�ģ����쳣��" + e.getMessage());
        }
    }

    /**
     * Attached��ǩ����ԭ�ĵ�ǩ��ֵ��SM2֤��
     */
    @Test(groups = "abcjew.attachedverify.normal")
    public void testattachedVerify_10() {
        System.out.println("Attached��ǩ(attachedVerify),��ԭ�ĵ�ǩ��ֵ,SM2֤��");
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
                Assert.fail(" ��E��ABCJEW-attached��ǩ�����Դ�ԭ�ģ�ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-attached��ǩ�����Դ�ԭ�ģ����쳣��" + e.getMessage());
        }
    }

    /**
     * Attached��ǩ��ʹ��Ĭ��ժҪ�㷨��ǩ��ֵ
     */
    @Test(groups = "abcjew.attachedverify.normal", dataProvider = "normal-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testattachedVerify_11(String dn) {
        System.out.println("Attached��ǩ(attachedVerify),ʹ��Ĭ��ժҪ�㷨��ǩ��ֵ");
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
                Assert.fail(" ��E��ABCJEW-attached��ǩ������Ĭ��ժҪ�㷨��ǩ��ֵ��ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-attached��ǩ������Ĭ��ժҪ�㷨��ǩ��ֵ�����쳣��" + e.getMessage());
        }
    }

    /**
     * Attached��ǩ��AlgСд��ǩ��ֵ
     */
    @Test(groups = "abcjew.attachedverify.normal", dataProvider = "normal-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testattachedVerify_12(String alg, String dn) {
        System.out.println("Attached��ǩ(attachedVerify),ʹ��СдժҪ�㷨��ǩ��ֵ");
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
                Assert.fail(" ��E��ABCJEW-attached��ǩ������СдժҪ�㷨��ǩ��ֵ��ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-attached��ǩ������СдժҪ�㷨��ǩ��ֵ�����쳣��" + e.getMessage());
        }
    }
}
