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
 * @Description: ��֤���������ǩ
 * <p>�������ǵ㣺</p>
 * <p>1��ʹ��RSA֤����ǩ����֤��״̬����</p>
 * <p>2��ʹ��RSA֤����ǩ����֤��״̬����</p>
 * <p>3��ʹ��RSA֤����ǩ����֤��״̬����</p>
 * <p>4��ʹ��SM2֤����ǩ����֤��״̬����</p>
 * <p>5��ʹ��SM2֤����ǩ����֤��״̬����</p>
 * <p>6��ʹ��SM2֤����ǩ����֤��״̬����</p>
 * <p>7��ԭ��Ϊnull</p>
 * <p>8������Ϊnull</p>
 * <p>9������Ϊ���ַ�</p>
 * <p>10��֤��Ϊ���ַ�</p>
 */
@Test(groups = "abcjew.rawverifybyx509cert")
public class TestRawVerifyByX509Cert {
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
     * ʹ��RSA֤����ǩ����֤��״̬����
     */
    @Test(groups = "abcjew.rawverifybyx509cert.normal", dataProvider = "normal-rsa-cert",
            dataProviderClass = NetSignDataProvider.class)
    public void testRawVerifyByX509Cert_01(X509Certificate cert) {
        System.out.println("��֤����������ǩ��rawVerify����ʹ��RSA֤����ǩ����֤��״̬����");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        String dn = cert.getSubjectDN().getName();
        String dalg = "sha1";
        UpkiResult upkiResult = agent.rawSign(plainText, dn, dalg);
        String sign_text = upkiResult.getResults().get("sign_text").toString();

        try {
            UpkiResult upkiResult1 = agent.rawVerify(plainText, sign_text, cert);
            if (upkiResult1.getReturnCode() != 0) {
                Assert.fail("��֤����������ǩ��rawVerify��ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("��֤����������ǩ��rawVerify��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ʹ��RSA֤����ǩ����֤��״̬����
     */
    @Test(groups = "abcjew.rawverifybyx509cert.normal", dataProvider = "expire-rsa-cert",
            dataProviderClass = NetSignDataProvider.class)
    public void testRawVerifyByX509Cert_02(X509Certificate cert) {
        System.out.println("��֤����������ǩ��rawVerify����ʹ��RSA֤����ǩ����֤��״̬����");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        String dn = cert.getSubjectDN().getName();
        String dalg = "sha1";
        UpkiResult upkiResult = agent.rawSign(plainText, dn, dalg);
        String sign_text = upkiResult.getResults().get("sign_text").toString();

        try {
            UpkiResult upkiResult1 = agent.rawVerify(plainText, sign_text, cert);
            if (upkiResult1.getReturnCode() != -100106) {
                Assert.fail("��֤����������ǩ��rawVerify��ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("��֤����������ǩ��rawVerify��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ʹ��RSA֤����ǩ����֤��״̬����
     */
    @Test(groups = "abcjew.rawverifybyx509cert.normal", dataProvider = "revoke-rsa-cert",
            dataProviderClass = NetSignDataProvider.class)
    public void testRawVerifyByX509Cert_03(X509Certificate cert) {
        System.out.println("��֤����������ǩ��rawVerify����ʹ��RSA֤����ǩ����֤��״̬����");
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
                Assert.fail("��֤����������ǩ��rawVerify��ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("��֤����������ǩ��rawVerify��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ʹ��SM2֤����ǩ����֤��״̬����
     */
    @Test(groups = "abcjew.rawverifybyx509cert.normal", dataProvider = "normal-sm2-cert",
            dataProviderClass = NetSignDataProvider.class)
    public void testRawVerifyByX509Cert_04(X509Certificate cert) {
        System.out.println("��֤����������ǩ��rawVerify����ʹ��SM2֤����ǩ����֤��״̬����");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        String dn = cert.getSubjectDN().getName();
        String dalg = "sm3";
        UpkiResult upkiResult = agent.rawSign(plainText, dn, dalg);
        String sign_text = upkiResult.getResults().get("sign_text").toString();

        try {
            UpkiResult upkiResult1 = agent.rawVerify(plainText, sign_text, cert);
            if (upkiResult1.getReturnCode() != 0) {
                Assert.fail("��֤����������ǩ��rawVerify��ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("��֤����������ǩ��rawVerify��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ʹ��SM2֤����ǩ����֤��״̬����
     */
    @Test(groups = "abcjew.rawverifybyx509cert.normal", dataProvider = "expire-sm2-cert",
            dataProviderClass = NetSignDataProvider.class)
    public void testRawVerifyByX509Cert_05(X509Certificate cert) {
        System.out.println("��֤����������ǩ��rawVerify����ʹ��SM2֤����ǩ����֤��״̬����");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        String dn = cert.getSubjectDN().getName();
        String dalg = "sm3";
        UpkiResult upkiResult = agent.rawSign(plainText, dn, dalg);
        String sign_text = upkiResult.getResults().get("sign_text").toString();

        try {
            UpkiResult upkiResult1 = agent.rawVerify(plainText, sign_text, cert);
            if (upkiResult1.getReturnCode() != -100106) {
                Assert.fail("��֤����������ǩ��rawVerify��ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("��֤����������ǩ��rawVerify��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ʹ��SM2֤����ǩ����֤��״̬����
     */
    @Test(groups = "abcjew.rawverifybyx509cert.normal", dataProvider = "revoke-sm2-cert",
            dataProviderClass = NetSignDataProvider.class)
    public void testRawVerifyByX509Cert_06(X509Certificate cert) {
        System.out.println("��֤����������ǩ��rawVerify����ʹ��SM2֤����ǩ����֤��״̬����");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        String dn = cert.getSubjectDN().getName();
        String dalg = "sm3";
        UpkiResult upkiResult = agent.rawSign(plainText, dn, dalg);
        String sign_text = upkiResult.getResults().get("sign_text").toString();

        try {
            UpkiResult upkiResult1 = agent.rawVerify(plainText, sign_text, cert);
            if (upkiResult1.getReturnCode() != -100108) {
                Assert.fail("��֤����������ǩ��rawVerify��ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("��֤����������ǩ��rawVerify��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ԭ��Ϊnull
     */
    @Test(groups = "abcjew.rawverifybyx509cert.normal", dataProvider = "normal-rsa-cert",
            dataProviderClass = NetSignDataProvider.class)
    public void testRawVerifyByX509Cert_07(X509Certificate cert) {
        System.out.println("��֤����������ǩ��rawVerify����ԭ��Ϊnull");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        String dn = cert.getSubjectDN().getName();
        String dalg = "sha1";
        UpkiResult upkiResult = agent.rawSign(plainText, dn, dalg);
        String sign_text = upkiResult.getResults().get("sign_text").toString();

        try {
            UpkiResult upkiResult1 = agent.rawVerify(null, sign_text, cert);
            if (upkiResult1.getReturnCode() != -1027) {
                Assert.fail("��֤����������ǩ��rawVerify��ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("��֤����������ǩ��rawVerify��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ����Ϊnull
     */
    @Test(groups = "abcjew.rawverifybyx509cert.normal", dataProvider = "normal-rsa-cert",
            dataProviderClass = NetSignDataProvider.class)
    public void testRawVerifyByX509Cert_08(X509Certificate cert) {
        System.out.println("��֤����������ǩ��rawVerify��������Ϊnull");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        String dn = cert.getSubjectDN().getName();
        String dalg = "sha1";
        UpkiResult upkiResult = agent.rawSign(plainText, dn, dalg);
        String sign_text = upkiResult.getResults().get("sign_text").toString();

        try {
            UpkiResult upkiResult1 = agent.rawVerify(plainText, null, cert);
            if (upkiResult1.getReturnCode() != -1027) {
                Assert.fail("��֤����������ǩ��rawVerify��ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("��֤����������ǩ��rawVerify��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ����Ϊ���ַ�
     */
    @Test(groups = "abcjew.rawverifybyx509cert.normal", dataProvider = "normal-rsa-cert",
            dataProviderClass = NetSignDataProvider.class)
    public void testRawVerifyByX509Cert_09(X509Certificate cert) {
        System.out.println("��֤����������ǩ��rawVerify��������Ϊ���ַ�");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        String dn = cert.getSubjectDN().getName();
        String dalg = "sha1";
        UpkiResult upkiResult = agent.rawSign(plainText, dn, dalg);
        String sign_text = upkiResult.getResults().get("sign_text").toString();

        try {
            UpkiResult upkiResult1 = agent.rawVerify(plainText, "", cert);
            if (upkiResult1.getReturnCode() != -100104) {
                Assert.fail("��֤����������ǩ��rawVerify��ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("��֤����������ǩ��rawVerify��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ֤��Ϊ���ַ�
     */
    @Test(groups = "abcjew.rawverifybyx509cert.normal", dataProvider = "normal-rsa-cert",
            dataProviderClass = NetSignDataProvider.class)
    public void testRawVerifyByX509Cert_10(X509Certificate cert) {
        System.out.println("��֤����������ǩ��rawVerify��������Ϊ���ַ�");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        String dn = cert.getSubjectDN().getName();
        String dalg = "sha1";
        UpkiResult upkiResult = agent.rawSign(plainText, dn, dalg);
        String sign_text = upkiResult.getResults().get("sign_text").toString();

        try {
            UpkiResult upkiResult1 = agent.rawVerify(plainText, sign_text, "");
            if (upkiResult1.getReturnCode() != -1) {
                Assert.fail("��֤����������ǩ��rawVerify��ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("��֤����������ǩ��rawVerify��ʧ�ܣ�" + e.getMessage());
        }
    }
}
