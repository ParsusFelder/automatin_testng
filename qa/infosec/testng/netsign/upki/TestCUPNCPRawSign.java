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
 * @ClassName: TestCUPNCPRawSign
 * @date 2020-03-23 10:19
 * @Description: ���������޿�֧����ǩ��
 * <p>�������ǵ㣺</p>
 * <p>1�����������޿�֧����ǩ����CUPNCPRawSign����ʹ��RSA/SM2֤��DN��ǩ��</p>
 * <p>2�����������޿�֧����ǩ����CUPNCPRawSign����ʹ��RSA/SM2֤��SN��ǩ��</p>
 * <p>3�����������޿�֧����ǩ����CUPNCPRawSign����ʹ��RSA/SM2֤��Bankcode��ǩ��</p>
 * <p>4�����������޿�֧����ǩ����CUPNCPRawSign����ԭ��Ϊnull</p>
 * <p>5�����������޿�֧����ǩ����CUPNCPRawSign����DN/SN/BankcodeΪ�ջ�null</p>
 * <p>6�����������޿�֧����ǩ����CUPNCPRawSign����DN����</p>
 * <p>7�����������޿�֧����ǩ����CUPNCPRawSign����ժҪ�㷨Ϊ�ջ�null</p>
 * <p>8�����������޿�֧����ǩ����CUPNCPRawSign����ժҪ�㷨����</p>
 * <p>9�����������޿�֧����ǩ����CUPNCPRawSign������ԭ����ǩ��,RSA֤��</p>
 * <p>9�����������޿�֧����ǩ����CUPNCPRawSign������ԭ����ǩ��,SM2֤��</p>
 */
@Test(groups = "abcjew.cupncprawsign")
public class TestCUPNCPRawSign {
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
     * ���������޿�֧����ǩ����CUPNCPRawSign����ʹ��RSA/SM2֤��DN��ǩ��
     *
     * @param alg ժҪ�㷨
     * @param dn  RSA/SM2֤��DN
     */
    @Test(groups = "abcjew.cupncprawsign.normal", dataProvider = "all-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawSign_01(String alg, String dn) {
        System.out.println("���������޿�֧����ǩ����CUPNCPRawSign����ʹ��RSA/SM2֤��DN��ǩ��");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        boolean bool_result;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (bool_result == false || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }
    }

    /**
     * ���������޿�֧����ǩ����CUPNCPRawSign����ʹ��RSA/SM2֤��SN��ǩ��
     *
     * @param alg ժҪ�㷨
     * @param sn  RSA/SM2֤��SN
     */
    @Test(groups = "abcjew.cupncprawsign.normal", dataProvider = "all-alg-sn", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawSign_02(String alg, String sn) {
        System.out.println("���������޿�֧����ǩ����CUPNCPRawSign����ʹ��RSA/SM2֤��SN��ǩ��");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        boolean bool_result;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, sn, alg);
            bool_result = upkiResult.getBoolResult();
            if (bool_result == false || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }
    }

    /**
     * ���������޿�֧����ǩ����CUPNCPRawSign����ʹ��RSA/SM2֤��Bankcode��ǩ��
     *
     * @param alg      ժҪ�㷨
     * @param bankcode RSA/SM2֤��Bankcode
     */
    @Test(groups = "abcjew.cupncprawsign.normal", dataProvider = "all-alg-bankcode", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawSign_03(String alg, String bankcode) {
        System.out.println("���������޿�֧����ǩ����CUPNCPRawSign����ʹ��RSA/SM2֤��Bankcode��ǩ��");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        boolean bool_result;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, bankcode, alg);
            bool_result = upkiResult.getBoolResult();
            if (bool_result == false || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }
    }

    /**
     * ���������޿�֧����ǩ����CUPNCPRawSign����ԭ��Ϊnull
     *
     */
    @Test(groups = "abcjew.cupncprawsign.normal")
    public void testCUPNCPRawSign_04() {
        System.out.println("���������޿�֧����ǩ����CUPNCPRawSign����ԭ��Ϊnull");

        UpkiResult upkiResult = null;
        boolean bool_result;
        String alg = "SHA1";
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            upkiResult = agent.CUPNCPRawSign(null, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (bool_result == true || upkiResult.getReturnCode() != -1026) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }
    }

    /**
     * ���������޿�֧����ǩ����CUPNCPRawSign����DN/SN/BankcodeΪ�ջ�null
     *
     * @param dn RSA/SM2֤��DN
     */
    @Test(groups = "abcjew.cupncprawsign.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawSign_05(String dn) {
        System.out.println("���������޿�֧����ǩ����CUPNCPRawSign����ʹ��RSA/SM2֤��DN��ǩ��");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        boolean bool_result;
        String alg = "SHA1";
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (bool_result == false || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            Reporter.log("���������޿�֧����ǩ����CUPNCPRawSign��:DN/SN/BankcodeΪ�ջ�null,��ǩ���ɹ�");
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }
    }

    /**
     * ���������޿�֧����ǩ����CUPNCPRawSign����DN����
     *
     */
    @Test(groups = "abcjew.cupncprawsign.normal")
    public void testCUPNCPRawSign_06() {
        System.out.println("���������޿�֧����ǩ����CUPNCPRawSign����DN����");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        boolean bool_result;
        String alg = "SHA1";
        String dn = "CN=123";
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (bool_result == true || upkiResult.getReturnCode() != -100204) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }
    }

    /**
     * ���������޿�֧����ǩ����CUPNCPRawSign����ժҪ�㷨Ϊ�ջ�null
     *
     */
    @Test(groups = "abcjew.cupncprawsign.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawSign_07(String alg) {
        System.out.println("���������޿�֧����ǩ����CUPNCPRawSign����ժҪ�㷨Ϊ�ջ�null");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        boolean bool_result;
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (bool_result == true || upkiResult.getReturnCode() != -1026) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }
    }

    /**
     * ���������޿�֧����ǩ����CUPNCPRawSign����ժҪ�㷨����
     *
     */
    @Test(groups = "abcjew.cupncprawsign.normal")
    public void testCUPNCPRawSign_08() {
        System.out.println("���������޿�֧����ǩ����CUPNCPRawSign����ժҪ�㷨����");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        boolean bool_result;
        String alg = "SHA3";
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (bool_result == true || upkiResult.getReturnCode() != -100112) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }
    }

    /**
     * ���������޿�֧����ǩ����CUPNCPRawSign������ԭ����ǩ��,RSA֤��
     *
     */
    @Test(groups = "abcjew.cupncprawsign.normal")
    public void testCUPNCPRawSign_09() {
        System.out.println("���������޿�֧����ǩ����CUPNCPRawSign������ԭ����ǩ��,RSA֤��");

        byte[] plainText = ParseFile.getFileData(ParameterUtil.bigfilepath);
        UpkiResult upkiResult = null;
        boolean bool_result;
        String alg = "SHA1";
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (bool_result == false || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }
    }

    /**
     * ���������޿�֧����ǩ����CUPNCPRawSign������ԭ����ǩ��,SM2֤��
     *
     */
    @Test(groups = "abcjew.cupncprawsign.normal")
    public void testCUPNCPRawSign_10() {
        System.out.println("���������޿�֧����ǩ����CUPNCPRawSign������ԭ����ǩ��,SM2֤��");

        byte[] plainText = ParseFile.getFileData(ParameterUtil.bigfilepath);
        UpkiResult upkiResult = null;
        boolean bool_result;
        String alg = "SM3";
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=SS019normal";
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (bool_result == false || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }
    }
}
