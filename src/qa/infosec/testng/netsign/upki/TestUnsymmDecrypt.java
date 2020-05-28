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
 * @ClassName: TestUnsymmDecrypt
 * @date 2020-03-02 18:02
 * @Description: �ǶԳƽ���
 * <p>�������ǵ㣺</p>
 * <p>1���ǶԳƽ��ܣ�DN��base64֤��ƥ��</p>
 * <p>2���ǶԳƽ��ܣ�SN��base64֤��ƥ��</p>
 * <p>3���ǶԳƽ��ܣ�ʹ��bankcode</p>
 * <p>4���ǶԳƽ��ܣ�bankcode��֤�����ݲ�ƥ��</p>
 * <p>5���ǶԳƽ��ܣ�DN/SN/BankCodeΪnull</p>
 * <p>6���ǶԳƽ��ܣ�DN/SN/BankCodeΪ���ַ�</p>
 * <p>7���ǶԳƽ��ܣ�����Ϊ�ջ�null</p>
 * <p>8���ǶԳƽ��ܣ����Ĵ۸�</p>
 * <p>9���ǶԳƽ��ܣ�DN/SN/BankCode����</p>
 */
@Test(groups = "abcjew.unsymmdecrypt")
public class TestUnsymmDecrypt {
    static String ip, port, password;
    static String host, sftp_port, sftp_password, sftp_user;

    NetSignServerInit init = new NetSignServerInit();
    UpkiAgent agent;
    SFTPFile tmp = new SFTPFile();

    {
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
    }

    /**
     * �ǶԳƽ��ܣ�DN��base64֤��ƥ��
     */
    @Test(groups = "abcjew.unsymmdecrypt.normal", dataProvider = "allcert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testUnsymmDecrypt_01(String str) {
        System.out.println("Test UnsymmDecrypt DN Normal");
        String[] split = str.split("%");
        String DN = split[0];
        String base64Cert = split[1];
        byte[] pOrgData = Utils.getRandomString(60).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String crypto = null;
        // ��ȡ�ǶԳƼ�������
        try {
            upkiResult = agent.unsymmEncrypt(DN, pOrgData, base64Cert);
            if (upkiResult == null || upkiResult.getReturnCode() != 0) {
                Assert.fail("�ǶԳƼ���ʧ�ܣ�" + upkiResult.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("�ǶԳƼ���ʧ�ܣ�" + upkiResult.getReturnCode() + e.getMessage());
        }
        // ���ܷǶԳƼ�������
        try {
            crypto = upkiResult.getResults().get(UpkiResult.STR_CONTENT).toString();
            upkiResult1 = agent.unsymmDecrypt(DN, crypto);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != 0) {
                Assert.fail("�ǶԳƽ���ʧ�ܣ�" + upkiResult1.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("�ǶԳƽ���ʧ�ܣ�" + upkiResult1.getReturnCode() + e.getMessage());
        }
    }

    /**
     * �ǶԳƽ��ܣ�SN��base64֤��ƥ��
     */
    @Test(groups = "abcjew.unsymmdecrypt.normal", dataProvider = "allcert-sn", dataProviderClass =
            NetSignDataProvider.class)
    public void testUnsymmDecrypt_02(String str) {
        System.out.println("Test UnsymmDecrypt SN Normal");
        String[] split = str.split("%");
        String SN = split[0];
        String base64Cert = split[1];
        byte[] pOrgData = Utils.getRandomString(60).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String crypto = null;
        // ��ȡ�ǶԳƼ�������
        try {
            upkiResult = agent.unsymmEncrypt(SN, pOrgData, base64Cert);
            if (upkiResult == null || upkiResult.getReturnCode() != 0) {
                Assert.fail("�ǶԳƼ���ʧ�ܣ�" + upkiResult.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("�ǶԳƼ���ʧ�ܣ�" + upkiResult.getReturnCode() + e.getMessage());
        }
        // ���ܷǶԳƼ�������
        try {
            crypto = upkiResult.getResults().get(UpkiResult.STR_CONTENT).toString();
            upkiResult1 = agent.unsymmDecrypt(SN, crypto);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != 0) {
                Assert.fail("�ǶԳƽ���ʧ�ܣ�" + upkiResult1.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("�ǶԳƽ���ʧ�ܣ�" + upkiResult1.getReturnCode() + e.getMessage());
        }
    }

    /**
     * �ǶԳƽ��ܣ�ʹ��bankcode
     */
    @Test(groups = "abcjew.unsymmdecrypt.normal", dataProvider = "bankcode", dataProviderClass =
            NetSignDataProvider.class)
    public void testUnsymmDecrypt_03(String bankcode) {
        System.out.println("Test UnsymmDecrypt BankCode Normal");
        byte[] pOrgData = Utils.getRandomString(60).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String crypto = null;
        // ��ȡ�ǶԳƼ�������
        if (!"10year".equals(bankcode)) {
            try {
                upkiResult = agent.unsymmEncrypt(bankcode, pOrgData, null);
                if (upkiResult == null || upkiResult.getReturnCode() != 0) {
                    Assert.fail("�ǶԳƼ���ʧ�ܣ�" + upkiResult.getReturnCode());
                }
            } catch (Exception e) {
                Assert.fail("�ǶԳƼ���ʧ�ܣ�" + upkiResult.getReturnCode() + e.getMessage());
            }

            // ���ܷǶԳƼ�������
            try {
                crypto = upkiResult.getResults().get(UpkiResult.STR_CONTENT).toString();
                upkiResult1 = agent.unsymmDecrypt(bankcode, crypto);
                if (upkiResult1 == null || upkiResult1.getReturnCode() != 0) {
                    Assert.fail("�ǶԳƽ���ʧ�ܣ�" + upkiResult1.getReturnCode());
                }
            } catch (Exception e) {
                Assert.fail("�ǶԳƽ���ʧ�ܣ�" + upkiResult1.getReturnCode() + e.getMessage());
            }
        }
    }

    /**
     * �ǶԳƽ��ܣ�bankcode��֤�����ݲ�ƥ��
     */
    @Test(groups = "abcjew.unsymmdecrypt.normal", dataProvider = "allcert-bankcode", dataProviderClass =
            NetSignDataProvider.class)
    public void testUnsymmDecrypt_04(String str) {
        System.out.println("Test UnsymmDecrypt BankCode Normal");
        byte[] pOrgData = Utils.getRandomString(60).getBytes();
        String[] split = str.split("%");
        String bankcode = split[0];
        String base64Cert = split[1];
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String crypto = null;
        // ��ȡ�ǶԳƼ�������
        if (!"10year".equals(bankcode)) {
            try {
                upkiResult = agent.unsymmEncrypt(bankcode, pOrgData, base64Cert);
                if (upkiResult == null || upkiResult.getReturnCode() != 0) {
                    Assert.fail("�ǶԳƼ���ʧ�ܣ�" + upkiResult.getReturnCode());
                }
            } catch (Exception e) {
                Assert.fail("�ǶԳƼ���ʧ�ܣ�" + upkiResult.getReturnCode() + e.getMessage());
            }

            // ���ܷǶԳƼ�������
            try {
                crypto = upkiResult.getResults().get(UpkiResult.STR_CONTENT).toString();
                upkiResult1 = agent.unsymmDecrypt(bankcode, crypto);
                if (upkiResult1.getReturnCode() != -100110) {
                    Assert.fail("�ǶԳƽ���ʧ�ܣ�" + upkiResult1.getReturnCode());
                }
            } catch (Exception e) {
                Assert.fail("�ǶԳƽ���ʧ�ܣ�" + upkiResult1.getReturnCode() + e.getMessage());
            }
        }
    }

    /**
     * �ǶԳƽ��ܣ�DN/SN/BankCodeΪnull
     */
    @Test(groups = "abcjew.unsymmdecrypt.normal", dataProvider = "allcert-sn", dataProviderClass =
            NetSignDataProvider.class)
    public void testUnsymmDecrypt_05(String str) {
        System.out.println("Test UnsymmDecrypt DN/SN/BankCode Null");
        String[] split = str.split("%");
        String SN = split[0];
        String base64Cert = split[1];
        byte[] pOrgData = Utils.getRandomString(60).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String crypto = null;
        // ��ȡ�ǶԳƼ�������
        try {
            upkiResult = agent.unsymmEncrypt(SN, pOrgData, base64Cert);
            if (upkiResult == null || upkiResult.getReturnCode() != 0) {
                Assert.fail("�ǶԳƼ���ʧ�ܣ�" + upkiResult.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("�ǶԳƼ���ʧ�ܣ�" + upkiResult.getReturnCode() + e.getMessage());
        }
        // ���ܷǶԳƼ�������
        try {
            crypto = upkiResult.getResults().get(UpkiResult.STR_CONTENT).toString();
            upkiResult1 = agent.unsymmDecrypt(null, crypto);
            if (upkiResult1.getReturnCode() != -100110) {
                if (upkiResult1.getReturnCode() != 0) {
                    Assert.fail("�ǶԳƽ���ʧ�ܣ�" + upkiResult1.getReturnCode());
                }
                Reporter.log("�ǶԳƽ��ܣ�UnsymmDecrypt�������ں�������֤�飬����ʱDN/SN/BankCode����Ϊ�����ܽ��ܳɹ�");
            }
        } catch (Exception e) {
            Assert.fail("�ǶԳƽ���ʧ�ܣ�" + upkiResult1.getReturnCode() + e.getMessage());
        }
    }

    /**
     * �ǶԳƽ��ܣ�DN/SN/BankCodeΪ���ַ�
     */
    @Test(groups = "abcjew.unsymmdecrypt.normal", dataProvider = "allcert-sn", dataProviderClass =
            NetSignDataProvider.class)
    public void testUnsymmDecrypt_06(String str) {
        System.out.println("Test UnsymmDecrypt DN/SN/BankCode Empty");
        String[] split = str.split("%");
        String SN = split[0];
        String base64Cert = split[1];
        byte[] pOrgData = Utils.getRandomString(60).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String crypto = null;
        // ��ȡ�ǶԳƼ�������
        try {
            upkiResult = agent.unsymmEncrypt(SN, pOrgData, base64Cert);
            if (upkiResult == null || upkiResult.getReturnCode() != 0) {
                Assert.fail("�ǶԳƼ���ʧ�ܣ�" + upkiResult.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("�ǶԳƼ���ʧ�ܣ�" + upkiResult.getReturnCode() + e.getMessage());
        }
        // ���ܷǶԳƼ�������
        try {
            crypto = upkiResult.getResults().get(UpkiResult.STR_CONTENT).toString();
            upkiResult1 = agent.unsymmDecrypt("", crypto);
            if (upkiResult1.getReturnCode() != -100110) {
                if (upkiResult1.getReturnCode() != 0) {
                    Assert.fail("�ǶԳƽ���ʧ�ܣ�" + upkiResult1.getReturnCode());
                }
                Reporter.log("�ǶԳƽ��ܣ�UnsymmDecrypt�������ں�������֤�飬����ʱDN/SN/BankCode����Ϊ�����ܽ��ܳɹ�");
            }
        } catch (Exception e) {
            Assert.fail("�ǶԳƽ���ʧ�ܣ�" + upkiResult1.getReturnCode() + e.getMessage());
        }
    }

    /**
     * �ǶԳƽ��ܣ�����Ϊ�ջ�null
     */
    @Test(groups = "abcjew.unsymmdecrypt.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testUnsymmDecrypt_07(String crypto) {
        System.out.println("Test UnsymmDecrypt Crypto Null or Empty");
        String sCertDN = "CN=c020crlfbdIssueModeCDP";
        UpkiResult upkiResult1 = null;
        // ���ܷǶԳƼ�������
        try {
            upkiResult1 = agent.unsymmDecrypt(sCertDN, crypto);
            if (upkiResult1.getReturnCode() != -100110 && upkiResult1.getReturnCode()!=-1022) {
                Assert.fail("�ǶԳƽ���ʧ�ܣ�" + upkiResult1.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("�ǶԳƽ���ʧ�ܣ�" + upkiResult1.getReturnCode() + e.getMessage());
        }
    }

    /**
     * �ǶԳƽ��ܣ����Ĵ۸�
     */
    @Test(groups = "abcjew.unsymmdecrypt.normal", dataProvider = "allcert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testUnsymmDecrypt_09(String str) {
        System.out.println("Test UnsymmDecrypt DN Error");
        String[] split = str.split("%");
        String DN = split[0];
        String base64Cert = split[1];
        byte[] pOrgData = Utils.getRandomString(60).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String crypto = null;
        // ��ȡ�ǶԳƼ�������
        try {
            upkiResult = agent.unsymmEncrypt(DN, pOrgData, base64Cert);
            if (upkiResult == null || upkiResult.getReturnCode() != 0) {
                Assert.fail("�ǶԳƼ���ʧ�ܣ�" + upkiResult.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("�ǶԳƼ���ʧ�ܣ�" + upkiResult.getReturnCode() + e.getMessage());
        }
        // ���ܷǶԳƼ�������
        try {
            crypto = upkiResult.getResults().get(UpkiResult.STR_CONTENT).toString();
            StringBuilder strBuilder = new StringBuilder(crypto);
            strBuilder.replace(5,10,"12345");
            crypto = strBuilder.toString();
            upkiResult1 = agent.unsymmDecrypt(DN, crypto);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != -100110) {
                Assert.fail("�ǶԳƽ���ʧ�ܣ�" + upkiResult1.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("�ǶԳƽ���ʧ�ܣ�" + upkiResult1.getReturnCode() + e.getMessage());
        }
    }

    /**
     * �ǶԳƽ��ܣ�DN����
     */
    @Test(groups = "abcjew.unsymmdecrypt.normal", dataProvider = "allcert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testUnsymmDecrypt_08(String str) {
        System.out.println("Test UnsymmDecrypt DN Error");
        String[] split = str.split("%");
        String DN = split[0];
        String base64Cert = split[1];
        byte[] pOrgData = Utils.getRandomString(60).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String crypto = null;
        // ��ȡ�ǶԳƼ�������
        try {
            upkiResult = agent.unsymmEncrypt(DN, pOrgData, base64Cert);
            if (upkiResult == null || upkiResult.getReturnCode() != 0) {
                Assert.fail("�ǶԳƼ���ʧ�ܣ�" + upkiResult.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("�ǶԳƼ���ʧ�ܣ�" + upkiResult.getReturnCode() + e.getMessage());
        }
        // ���ܷǶԳƼ�������
        try {
            crypto = upkiResult.getResults().get(UpkiResult.STR_CONTENT).toString();
            upkiResult1 = agent.unsymmDecrypt("CN=123", crypto);
            if (upkiResult1 == null || upkiResult1.getReturnCode() != -100203) {
                Assert.fail("�ǶԳƽ���ʧ�ܣ�" + upkiResult1.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("�ǶԳƽ���ʧ�ܣ�" + upkiResult1.getReturnCode() + e.getMessage());
        }
    }
}
