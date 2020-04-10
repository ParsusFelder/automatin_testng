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
 * <p>�������ǵ㣺</p>
 * ��Ϊ��detached��ǩ��֧��SHA1��SHA256�㷨���ʽ�RSA��SM2��Ϊ2������
 * <p>1��RSA֤����ǩ</p>
 * <p>2��SM2֤����ǩ</p>
 * <p>3��ǩ��ֵ���۸�</p>
 * <p>4��ǩ��ֵΪ�ջ���null</p>
 * <p>5��ǩ��֤���ѹ���</p>
 * <p>6��ǩ��֤��������</p>
 * <p>7��ǩ��֤�鲻������</p>
 * <p>8����ǩ֤�鲻����</p>
 * <p>9����Կ��RSA֤��sn��ǩ��ֵ</p>
 * <p>10����Կ��SM2֤��sn��ǩ��ֵ</p>
 * <p>11��ʹ��Ĭ��ժҪ�㷨��ǩ��ֵ</p>
 * <p>12��ʹ��RSA����СдժҪ�㷨��ǩ��ֵ</p>
 * <p>13��ʹ��SM2����СдժҪ�㷨��ǩ��ֵ</p>
 * <p>14��ԭ�Ĳ�һ��</p>
 * <p>15��ԭ��Ϊnull</p>
 * <p>16��ԭ��Ϊ��</p>
 */
public class TestDetachedVerify {
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
     * ���ڴ˽ӿڹ�����ǩʹ��SHA1��SHA256�㷨�����ʽ�RSA��SM2������������
     * Detached��ǩ������������,RSA
     */
    @Test(groups = "abcjew.detachedverify.normal", dataProvider = "rsadn-normal-alg", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedVerify_01(String dn, String alg) {
        System.out.println("Detached��ǩ(detachedVerify),����������,RSA֤��");
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
                Assert.fail(" ��E��ABCJEW-detached��ǩ�����Դ��ξ�����RSA��ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-detached��ǩ�����Դ��ξ�����RSA�����쳣��" + e.getMessage());
        }
    }

    /**
     * Detached��ǩ������������,SM2
     */
    @Test(groups = "abcjew.detachedverify.normal", dataProvider = "sm2dn-normal-alg", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedVerify_02(String dn, String alg) {
        System.out.println("Detached��ǩ(detachedVerify),����������,SM2֤��");
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
                    Assert.fail(" ��E��ABCJEW-detached��ǩ������SM2֤�飬SM3ժҪ�㷨��ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
                }
            }
            else {
                if (verify.getReturnCode() != 0) {
                    if (verify.getReturnCode() != -100129) {
                        Assert.fail(" ��E��ABCJEW-detached��ǩ������SM2֤�飬SHA1��SHA256ժҪ�㷨��ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
                    }
                    Reporter.log("��E��ABCJEW-detached��ǩ������SM2֤�飬SHA1��SHA256ժҪ�㷨��֧��");
                }
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-detached��ǩ������SM2֤�飬���쳣��" + e.getMessage());
        }
    }

    /**
     * Detached��ǩ��ǩ��ֵ���۸�
     */
    @Test(groups = "abcjew.detachedverify.normal", dataProvider = "normal-alg-dn", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedVerify_03(String alg, String dn) {
        System.out.println("Detached��ǩ(detachedVerify),ǩ��ֵ���۸�");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.detachedSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            // �޸�ǩ�����
            StringBuilder sb = new StringBuilder(signresult);
            sb.replace(signresult.length() - 5, signresult.length() - 2, "BCD");
            String new_sign_result;
            new_sign_result = sb.toString();
            verify = agent.detachedVerify( pOrgData, new_sign_result);
            if (verify.getBoolResult() != false || verify.getReturnCode() != -100104) {
                Assert.fail(" ��E��ABCJEW-attached��ǩ�����Ա��۸ĵ�ǩ��ֵ��ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-attached��ǩ�����Ա��۸ĵ�ǩ��ֵ�����쳣��" + e.getMessage());
        }
    }

    /**
     * Detached��ǩ��ǩ��ֵΪ�ջ���null
     */
    @Test(groups = "abcjew.detachedverify.normal", dataProvider = "emptys-parameter", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedVerify_04(String sign) {
        System.out.println("Detached��ǩ(detachedVerify),ǩ��ֵΪ�ջ���null");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult verify;
            verify = agent.detachedVerify( pOrgData, sign);
            if (verify.getReturnCode() != -1011) {
                if (verify.getReturnCode() != -100100) {
                    Assert.fail(" ��E��ABCJEW-detached��ǩ������ǩ��ֵΪ�ջ���null��ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-detached��ǩ������ǩ��ֵΪ�ջ���null�����쳣��" + e.getMessage());
        }
    }

    /**
     * Detached��ǩ������֤��
     */
    @Test(groups = "abcjew.detachedverify.normal", dataProvider = "expire-alg-dn", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedVerify_05(String alg, String dn) {
        System.out.println("Detached��ǩ(detachedVerify),֤�����");
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
                Assert.fail(" ��E��ABCJEW-detached��ǩ�����Թ���֤�飬ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-detached��ǩ�����Թ���֤�飬���쳣��" + e.getMessage());
        }
    }

    /**
     * Detached��ǩ������֤��
     */
    @Test(groups = "abcjew.detachedverify.normal", dataProvider = "revoke-alg-dn", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedVerify_06(String alg, String dn) {
        System.out.println("Detached��ǩ(detachedVerify),֤������");
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
                    Assert.fail(" ��E��ABCJEW-detached��ǩ����������֤�飬ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-detached��ǩ����������֤�飬���쳣��" + e.getMessage());
        }
    }

    /**
     * Detached��ǩ����������֤��
     */
    @Test(groups = "abcjew.detachedverify.normal", dataProvider = "nottrust-alg-dn", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedVerify_07(String alg, String dn) {
        System.out.println("Detached��ǩ(detachedVerify),֤�鲻������");
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
                Assert.fail(" ��E��ABCJEW-detached��ǩ�����Բ�������֤�飬ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-detached��ǩ�����Բ�������֤�飬���쳣��" + e.getMessage());
        }
    }

    /**
     * Detached��ǩ�������������ڹ�Կ֤�飬��Ӧ��ǩ�ɹ�
     */
    @Test(groups = "abcjew.detachedverify.normal")
    public void testdetachedVerify_08() {
        System.out.println("Detached��ǩ(detachedVerify),�����������ڹ�Կ֤����Ӧ��ǩ�ɹ�");
        try {
            UpkiResult verify;
            String signresult = "MIIFeAYJKoZIhvcNAQcCoIIFaTCCBWUCAQExDzANBglghkgBZQMEAgEFADALBgkqhkiG9w0BBwGgggO9MIIDuTCCAqGgAwIBAgIFO1OkHnUwDQYJKoZIhvcNAQELBQAwSzELMAkGA1UEBhMCY24xJjAkBgNVBAoMHUlORk9TRUMgVGVjaG5vbG9naWVzIFNIQTI1NklEMRQwEgYDVQQDDAthcHBTSEEyNTZJRDAeFw0xNzExMjEwMjU3MDdaFw0yNjA4MTIwMjQ3MTRaMCwxCzAJBgNVBAYTAkNOMQswCQYDVQQKDAJRQTEQMA4GA1UEAwwHQ1NfMjA0ODCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMNoA9fcSXJyB5qRoa4ihJVL3MLXgQbreUL7KW4iiSwMPvn+dNVSU6VQ7iOqe+B8FcYcou2cnoBJEngnXh4ahVUlPyUHArkhOC/M7+2CKo/U3uJt7XdCv+NecSREAWZO2rRO2npkEKSD9ekmqFkx/QMIjA55RM628Nfq5hjmR1BMEdMxFW1TAzIqA/5xGaMENPV8v9TXv39wwlnbxN+WujOQ3Y4asObWmAn+UVIEu6RcXKw2j8+13svFgL1b89CXzhPSUZp/3TcAFXxqKY/mRr6uJEcrIEPHoPhVc1pO62PqPLfoNxnI88VoNZsVT6gfE3mvZmaJVjwmsbvYzJFoMiUCAwEAAaOBwjCBvzAfBgNVHSMEGDAWgBR+2NS35iQoLVNxo+cuS6rAo9y7GDAJBgNVHRMEAjAAMGUGA1UdHwReMFwwWqBYoFakVDBSMQ0wCwYDVQQDDARjcmw1MQwwCgYDVQQLDANjcmwxJjAkBgNVBAoMHUlORk9TRUMgVGVjaG5vbG9naWVzIFNIQTI1NklEMQswCQYDVQQGEwJjbjALBgNVHQ8EBAMCB4AwHQYDVR0OBBYEFKsJRzbUvBL7+Z7oN06vgdQYk75mMA0GCSqGSIb3DQEBCwUAA4IBAQAtyW8Kkh7ScvyZP7YR+Ma48rfJiE7/5o4h9QAfmTwc2RNbyH1VGKDR6vcOKa4PF3+8XPv2QZOOmRnr0sm15H4XCzp4mOy7seiZyzLGS7/7+iBRE1WVMHa5dkbxGN/R9p0EKPD6ZFbgcJtKhcOCzi3ZTDn9ubLPy803QgUJfkuMKVxdQ4ZdD6iBUQTuuwARATJ8Pc5fYQX9quiUUnWj2Pi7f8zkNRVlFrOd2Uu1s45yfXJ3i4WrOG3NGbEzLDBpDMcd36qf+Z95KysUadlvtWA+djnK3UrG3HZ8HmWCQ4mOgHMz4UisCo6DjW+jo2VnC70e8OG1rjVLvXXmr4mmUD1nMYIBfzCCAXsCAQEwVDBLMQswCQYDVQQGEwJjbjEmMCQGA1UECgwdSU5GT1NFQyBUZWNobm9sb2dpZXMgU0hBMjU2SUQxFDASBgNVBAMMC2FwcFNIQTI1NklEAgU7U6QedTANBglghkgBZQMEAgEFADANBgkqhkiG9w0BAQEFAASCAQC49ZbN6su7XPlYDYKPyyJ7wNWXM90+sM9amQWx5WvisKMyzyXzbRJDAGR5o0g1Rs5SJQapp6B3ISBo7rfNPncKetIdNsAL4S1OELyWp2o6eVd9Qe3Tgtq/fnSJCuLrDwEmPj9obzXSTnzxJ4+WqNNCdnuUFKAaMry0kf8/FUqOYqjclKS8xLDuEykKUKJJhcAHuihfYNN+3du/QVSPMx4DH1Px1yxbDIpLTA0iqd/EqWV54iAjQbbmqRHVzbcUtQ5TdJD9qAB1QDaJT2hmb0rtp2gnTjyybp3KBfkGGCU9bdkEWLIGvWJGzVtgkXhzYJ1LygqKpM7g5iHhI0eH7skM";
            verify = agent.detachedVerify("asd".getBytes(), signresult);
            if (verify.getBoolResult() != true || verify.getReturnCode() != 0
                    || !"success".equals(verify.getReturnContent())) {
                Assert.fail(" ��E��ABCJEW-detached��ǩ�����Է����������ڹ�Կ֤���Ƿ���ǩ�ɹ���ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-detached��ǩ�����Է����������ڹ�Կ֤���Ƿ���ǩ�ɹ������쳣��" + e.getMessage());
        }
    }

    /**
     * Dettached��ǩ����Կ��RSA֤��SN��ǩ��ֵ
     */
    @Test(groups = "abcjew.detachedverify.normal", dataProvider = "normal-rsa-sn-dalg", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedVerify_09(String sn, String alg) {
        System.out.println("Detached��ǩ(detachedVerify),��Կ��RSA֤��SN��ǩ��ֵ");
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
                Assert.fail(" ��E��ABCJEW-detached��ǩ������RSA��Կ֤�鴫SN��ǩ��ֵ��ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-detached��ǩ������RSA��Կ֤�鴫SN��ǩ��ֵ�����쳣��" + e.getMessage());
        }
    }


    /**
     * Detached��ǩ����Կ��SM2֤��SN��ǩ��ֵ
     */
    @Test(groups = "abcjew.detachedverify.normal", dataProvider = "normal-sm2-sn-dalg", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedVerify_10(String sn, String alg) {
        System.out.println("Detached��ǩ(detachedVerify),��Կ��SM2֤��SN��ǩ��ֵ");
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
                    Assert.fail(" ��E��ABCJEW-detached��ǩ������SM2��Կ֤�鴫SN��ǩ��ֵ��ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-detached��ǩ������SM2��Կ֤�鴫SN��ǩ��ֵ�����쳣��" + e.getMessage());
        }
    }

    /**
     * Detached��ǩ��ʹ��Ĭ��ժҪ�㷨��ǩ��ֵ
     */
    @Test(groups = "abcjew.detachedverify.normal", dataProvider = "normal-dn", dataProviderClass = NetSignDataProvider.class)
    public void  testdetachedVerify_11(String dn) {
        System.out.println("Detached��ǩ(detachedVerify),ʹ��Ĭ��ժҪ�㷨��ǩ��ֵ");
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
                Assert.fail(" ��E��ABCJEW-detached��ǩ������Ĭ��ժҪ�㷨��ǩ��ֵ��ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-detached��ǩ������Ĭ��ժҪ�㷨��ǩ��ֵ�����쳣��" + e.getMessage());
        }
    }

    /**
     * Detached��ǩ��RSA֤��AlgСд��ǩ��ֵ
     */
    @Test(groups = "abcjew.detachedverify.normal", dataProvider = "rsadn-normal-alg", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedVerify_12(String dn, String alg) {
        System.out.println("Detached��ǩ(detachedVerify),RSA֤��СдժҪ�㷨��ǩ��ֵ");
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
                Assert.fail(" ��E��ABCJEW-detached��ǩ������RSA����СдժҪ�㷨��ǩ��ֵ��ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-detached��ǩ������RSA����СдժҪ�㷨��ǩ��ֵ�����쳣��" + e.getMessage());
        }
    }

    /**
     * Detached��ǩ��SM2֤��AlgСд��ǩ��ֵ
     */
    @Test(groups = "abcjew.detachedverify.normal", dataProvider = "sm2dn-normal-alg", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedVerify_13(String dn, String alg) {
        System.out.println("Detached��ǩ(detachedVerify),SM2֤��СдժҪ�㷨��ǩ��ֵ");
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
                    Assert.fail(" ��E��ABCJEW-detached��ǩ������SM2֤�飬СдժҪ�㷨��ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-detached��ǩ������SM2֤�飬СдժҪ�㷨��ǩ��ֵ�����쳣��" + e.getMessage());
        }
    }

    /**
     * Detached��ǩ��ԭ�Ĳ�һ��
     */
    @Test(groups = "abcjew.detachedverify.normal", dataProvider = "normal-alg-dn", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedVerify_14(String alg, String dn) {
        System.out.println("Detached��ǩ(detachedVerify),ԭ�Ĳ�һ��");
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.detachedSign("aaa".getBytes(), dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();

            verify = agent.detachedVerify("basdd".getBytes(), signresult);
            if (verify.getReturnCode() != -100104) {
                Assert.fail(" ��E��ABCJEW-detached��ǩ������ԭ�Ĳ�һ�£�ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-detached��ǩ������ԭ�Ĳ�һ�£����쳣��" + e.getMessage());
        }
    }

    /**
     * Detached��ǩ��ԭ��Ϊnull
     */
    @Test(groups = "abcjew.detachedverify.normal", dataProvider = "normal-alg-dn", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedVerify_15(String alg, String dn) {
        System.out.println("Detached��ǩ(detachedVerify),ԭ��Ϊnull");
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.detachedSign("asd".getBytes(), dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();

            verify = agent.detachedVerify(null, signresult);
            if (verify.getReturnCode() != -100208) {
                Assert.fail(" ��E��ABCJEW-Detached��ǩ������ԭ��Ϊnull��ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-Detached��ǩ������ԭ��Ϊnull�����쳣��" + e.getMessage());
        }
    }

    /**
     * Detached��ǩ��ԭ��Ϊ��
     */
    @Test(groups = "abcjew.detachedverify.normal", dataProvider = "normal-alg-dn", dataProviderClass = NetSignDataProvider.class)
    public void testdetachedVerify_16(String alg, String dn) {
        System.out.println("Detached��ǩ(detachedVerify),ԭ��Ϊ��");
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.detachedSign("asd".getBytes(), dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();

            verify = agent.detachedVerify("".getBytes(), signresult);
            if (verify.getReturnCode() != -100104) {
                Assert.fail(" ��E��ABCJEW-Detached��ǩ������ԭ��Ϊ�գ�ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW-Detached��ǩ������ԭ��Ϊ�գ����쳣��" + e.getMessage());
        }
    }

}
