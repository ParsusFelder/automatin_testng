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
 * @author zhaoyongzhi
 * @ClassName: TestRawVerifyByBase64Cert
 * @date 2020-04-13 09:20
 * @Description: ��֤���������ǩ
 * <p>�������ǵ㣺</p>
 * <p>1��ʹ��RSAbase64֤����ǩ����֤��״̬����</p>
 * <p>2��ʹ��RSAbase64֤����ǩ����֤��״̬����</p>
 * <p>3��ʹ��RSAbase64֤����ǩ����֤��״̬��������</p>
 * <p>4��ʹ��RSAbase64֤����ǩ����֤��״̬����</p>
 * <p>5��ʹ��SM2֤����ǩ����֤��״̬����</p>
 * <p>6��ʹ��SM2֤����ǩ����֤��״̬����</p>
 * <p>7��ʹ��SM2֤����ǩ����֤��״̬����</p>
 * <p>8��ԭ��Ϊnull</p>
 * <p>9������Ϊnull</p>
 * <p>10������Ϊ���ַ�</p>
 * <p>11��֤��Ϊ���ַ�</p>
 */
@Test(groups = "abcjew.rawverifybybase64cert")
public class TestRawVerifyByBase64Cert {
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
     * ʹ��RSAbase64֤����ǩ����֤��״̬����
     */
    @Test(groups = "abcjew.rawverifybybase64cert.normal", dataProvider = "normal-rsa-base64cert-dn",
            dataProviderClass = NetSignDataProvider.class)
    public void testRawVerifyByBase64Cert_01(String strs) {
        System.out.println("��֤���������ǩ��rawVerify����ʹ��base64֤����ǩ����֤��״̬����");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        String[] split = strs.split("%");
        String dn = split[0];
        String base64cert = split[1];
        String dalg = "sha1";
        UpkiResult upkiResult = agent.rawSign(plainText, dn, dalg);
        String sign_text = upkiResult.getResults().get("sign_text").toString();

        try {
            UpkiResult upkiResult1 = agent.rawVerify(plainText, sign_text, base64cert);
            if (upkiResult1.getReturnCode() != 0) {
                Assert.fail("��֤���������ǩ��rawVerify��ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("��֤���������ǩ��rawVerify��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ʹ��RSAbase64֤����ǩ����֤��״̬����
     */
    @Test(groups = "abcjew.rawverifybybase64cert.normal", dataProvider = "expire-rsa-base64cert-dn",
            dataProviderClass = NetSignDataProvider.class)
    public void testRawVerifyByBase64Cert_02(String strs) {
        System.out.println("��֤���������ǩ��rawVerify����ʹ��base64֤����ǩ����֤��״̬����");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        String[] split = strs.split("%");
        String dn = split[0];
        String base64cert = split[1];
        String dalg = "sha1";
        UpkiResult upkiResult = agent.rawSign(plainText, dn, dalg);
        String sign_text = upkiResult.getResults().get("sign_text").toString();

        try {
            UpkiResult upkiResult1 = agent.rawVerify(plainText, sign_text, base64cert);
            if (upkiResult1.getReturnCode() != -100106) {
                Assert.fail("��֤���������ǩ��rawVerify��ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("��֤���������ǩ��rawVerify��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ʹ��RSAbase64֤����ǩ����֤��״̬��������
     */
    @Test(groups = "abcjew.rawverifybybase64cert.normal", dataProvider = "nottrust-rsa-base64cert-dn",
            dataProviderClass = NetSignDataProvider.class)
    public void testRawVerifyByBase64Cert_03(String strs) {
        System.out.println("��֤���������ǩ��rawVerify����ʹ��base64֤����ǩ����֤��״̬��������");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        String[] split = strs.split("%");
        String dn = split[0];
        String base64cert = split[1];
        String dalg = "sha1";
        UpkiResult upkiResult = agent.rawSign(plainText, dn, dalg);
        String sign_text = upkiResult.getResults().get("sign_text").toString();

        try {
            UpkiResult upkiResult1 = agent.rawVerify(plainText, sign_text, base64cert);
            if (upkiResult1.getReturnCode() != -100124 && upkiResult1.getReturnCode() != -100106) {
                Assert.fail("��֤���������ǩ��rawVerify��ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("��֤���������ǩ��rawVerify��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ʹ��RSAbase64֤����ǩ����֤��״̬����
     */
    @Test(groups = "abcjew.rawverifybybase64cert.normal", dataProvider = "revoke-rsa-base64cert-dn",
            dataProviderClass = NetSignDataProvider.class)
    public void testRawVerifyByBase64Cert_04(String strs) {
        System.out.println("��֤���������ǩ��rawVerify����ʹ��base64֤����ǩ����֤��״̬����");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        String[] split = strs.split("%");
        String dn = split[0];
        String base64cert = split[1];
        String dalg = "sha1";
        if ("C=CN,O=infosec,CN=C020revokedNocrlfile".equals(dn) || ("C=CN,O=infosec,OU=test3," +
                "CN=C020revokeMatchingAnyCrlfbd").equals(dn)) {
            return;
        }
        UpkiResult upkiResult = agent.rawSign(plainText, dn, dalg);
        String sign_text = upkiResult.getResults().get("sign_text").toString();
        System.out.println(dn);
        try {
            UpkiResult upkiResult1 = agent.rawVerify(plainText, sign_text, base64cert);
            if (upkiResult1.getReturnCode() != -100108) {
                Assert.fail("��֤���������ǩ��rawVerify��ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("��֤���������ǩ��rawVerify��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ʹ��SM2֤����ǩ����֤��״̬����
     */
    @Test(groups = "abcjew.rawverifybybase64cert.normal", dataProvider = "normal-sm2-base64cert-dn",
            dataProviderClass = NetSignDataProvider.class)
    public void testRawVerifyByBase64Cert_05(String strs) {
        System.out.println("��֤���������ǩ��rawVerify����ʹ��base64֤����ǩ����֤��״̬����");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        String[] split = strs.split("%");
        String dn = split[0];
        String base64cert = split[1];
        String dalg = "SM3";
        UpkiResult upkiResult = agent.rawSign(plainText, dn, dalg);
        String sign_text = upkiResult.getResults().get("sign_text").toString();

        try {
            UpkiResult upkiResult1 = agent.rawVerify(plainText, sign_text, base64cert);
            if (upkiResult1.getReturnCode() != 0) {
                Assert.fail("��֤���������ǩ��rawVerify��ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("��֤���������ǩ��rawVerify��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ʹ��SM2֤����ǩ����֤��״̬����
     */
    @Test(groups = "abcjew.rawverifybybase64cert.normal", dataProvider = "expire-sm2-base64cert-dn",
            dataProviderClass = NetSignDataProvider.class)
    public void testRawVerifyByBase64Cert_06(String strs) {
        System.out.println("��֤���������ǩ��rawVerify����ʹ��base64֤����ǩ����֤��״̬����");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        String[] split = strs.split("%");
        String dn = split[0];
        String base64cert = split[1];
        String dalg = "sm3";
        UpkiResult upkiResult = agent.rawSign(plainText, dn, dalg);
        String sign_text = upkiResult.getResults().get("sign_text").toString();

        try {
            UpkiResult upkiResult1 = agent.rawVerify(plainText, sign_text, base64cert);
            if (upkiResult1.getReturnCode() != -100106) {
                Assert.fail("��֤���������ǩ��rawVerify��ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("��֤���������ǩ��rawVerify��ʧ�ܣ�" + e.getMessage());
        }
    }


    /**
     * ʹ��SM2֤����ǩ����֤��״̬����
     */
    @Test(groups = "abcjew.rawverifybybase64cert.normal", dataProvider = "revoke-sm2-base64cert-dn",
            dataProviderClass = NetSignDataProvider.class)
    public void testRawVerifyByBase64Cert_07(String strs) {
        System.out.println("��֤���������ǩ��rawVerify����ʹ��base64֤����ǩ����֤��״̬����");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        String[] split = strs.split("%");
        String dn = split[0];
        String base64cert = split[1];
        String dalg = "sm3";
        UpkiResult upkiResult = agent.rawSign(plainText, dn, dalg);
        String sign_text = upkiResult.getResults().get("sign_text").toString();
        System.out.println(dn);
        try {
            UpkiResult upkiResult1 = agent.rawVerify(plainText, sign_text, base64cert);
            if (upkiResult1.getReturnCode() != -100108) {
                Assert.fail("��֤���������ǩ��rawVerify��ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("��֤���������ǩ��rawVerify��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ԭ��Ϊnull
     */
    @Test(groups = "abcjew.rawverifybybase64cert.normal", dataProvider = "normal-rsa-base64cert-dn",
            dataProviderClass = NetSignDataProvider.class)
    public void testRawVerifyByBase64Cert_08(String strs) {
        System.out.println("��֤���������ǩ��rawVerify����ԭ��Ϊnull");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        String[] split = strs.split("%");
        String dn = split[0];
        String base64cert = split[1];
        String dalg = "sha1";
        UpkiResult upkiResult = agent.rawSign(plainText, dn, dalg);
        String sign_text = upkiResult.getResults().get("sign_text").toString();

        try {
            UpkiResult upkiResult1 = agent.rawVerify(null, sign_text, base64cert);
            if (upkiResult1.getReturnCode() != -1027) {
                Assert.fail("��֤���������ǩ��rawVerify��ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("��֤���������ǩ��rawVerify��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ����Ϊnull
     */
    @Test(groups = "abcjew.rawverifybybase64cert.normal", dataProvider = "normal-rsa-base64cert-dn",
            dataProviderClass = NetSignDataProvider.class)
    public void testRawVerifyByBase64Cert_09(String strs) {
        System.out.println("��֤���������ǩ��rawVerify��������Ϊnull");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        String[] split = strs.split("%");
        String dn = split[0];
        String base64cert = split[1];
        String dalg = "sha1";
        UpkiResult upkiResult = agent.rawSign(plainText, dn, dalg);
        String sign_text = upkiResult.getResults().get("sign_text").toString();

        try {
            UpkiResult upkiResult1 = agent.rawVerify(plainText, null, base64cert);
            if (upkiResult1.getReturnCode() != -1027) {
                Assert.fail("��֤���������ǩ��rawVerify��ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("��֤���������ǩ��rawVerify��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ����Ϊ���ַ�
     */
    @Test(groups = "abcjew.rawverifybybase64cert.normal", dataProvider = "normal-rsa-base64cert-dn",
            dataProviderClass = NetSignDataProvider.class)
    public void testRawVerifyByBase64Cert_10(String strs) {
        System.out.println("��֤���������ǩ��rawVerify��������Ϊnull");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        String[] split = strs.split("%");
        String dn = split[0];
        String base64cert = split[1];
        String dalg = "sha1";
        UpkiResult upkiResult = agent.rawSign(plainText, dn, dalg);
        String sign_text = upkiResult.getResults().get("sign_text").toString();

        try {
            UpkiResult upkiResult1 = agent.rawVerify(plainText, "", base64cert);
            if (upkiResult1.getReturnCode() != -100104) {
                Assert.fail("��֤���������ǩ��rawVerify��ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("��֤���������ǩ��rawVerify��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ֤��Ϊ���ַ�
     */
    @Test(groups = "abcjew.rawverifybybase64cert.normal", dataProvider = "normal-rsa-base64cert-dn",
            dataProviderClass = NetSignDataProvider.class)
    public void testRawVerifyByBase64Cert_11(String strs) {
        System.out.println("��֤���������ǩ��rawVerify����֤��Ϊ���ַ�");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        String[] split = strs.split("%");
        String dn = split[0];
        String base64cert = split[1];
        String dalg = "sha1";
        UpkiResult upkiResult = agent.rawSign(plainText, dn, dalg);
        String sign_text = upkiResult.getResults().get("sign_text").toString();

        try {
            UpkiResult upkiResult1 = agent.rawVerify(plainText, sign_text, "");
            if (upkiResult1.getReturnCode() != -1) {
                Assert.fail("��֤���������ǩ��rawVerify��ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("��֤���������ǩ��rawVerify��ʧ�ܣ�" + e.getMessage());
        }
    }

}
