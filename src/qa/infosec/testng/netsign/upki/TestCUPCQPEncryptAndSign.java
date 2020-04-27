package qa.infosec.testng.netsign.upki;

import cn.com.infosec.netsign.agent.UpkiAgent;
import cn.com.infosec.netsign.agent.UpkiResult;
import cn.com.infosec.netsign.json.JsonObject;
import cn.com.infosec.netsign.json.JsonValueString;
import org.testng.Assert;
import org.testng.Reporter;
import org.testng.annotations.Test;
import qa.infosec.testng.netsign.dataprovider.NetSignDataProvider;
import qa.infosec.testng.netsign.dataprovider.util.*;
import qa.infosec.testng.netsign.init.NetSignServerInit;

import java.util.Map;
import java.util.Random;

import static qa.infosec.testng.netsign.dataprovider.util.JsonMessage.*;

/**
 * @author zhaoyongzhi
 * @ClassName: TestCUPCQPEncryptAndSign
 * @date 2020-04-26 18:17
 * @Description: ���������ܲ�ǩ��
 * <p>�������ǵ㣺</p>
 * <p>1�����������ܲ�ǩ����ʹ������״̬֤��DN���м��ܲ�ǩ��</p>
 * <p>2�����������ܲ�ǩ����ʹ������״̬֤��SN���м��ܲ�ǩ��</p>
 * <p>3�����������ܲ�ǩ����ʹ������״̬֤��Bankcode���м��ܲ�ǩ��</p>
 * <p>4�����������ܲ�ǩ�������ں�������֤��Bankcode���м��ܲ�ǩ��</p>
 * <p>5�����������ܲ�ǩ����appId�м���ֵ��ֵ����Ӣ�Ĵ�Сд�����ַ�</p>
 * <p>6�����������ܲ�ǩ����appId�м���ֵ</p>
 * <p>7�����������ܲ�ǩ����appId�޼���ֵ</p>
 * <p>8�����������ܲ�ǩ����indUsrId�м���ֵ��ֵ����Ӣ�Ĵ�Сд�����ַ�</p>
 * <p>9�����������ܲ�ǩ����indUsrId�м���ֵ</p>
 * <p>10�����������ܲ�ǩ����indUsrId�޼���ֵ</p>
 * <p>11�����������ܲ�ǩ����nonceStr�м���ֵ��ֵ����Ӣ�Ĵ�Сд�����ַ�</p>
 * <p>12�����������ܲ�ǩ����nonceStr�м���ֵ</p>
 * <p>13�����������ܲ�ǩ����nonceStr�޼���ֵ</p>
 * <p>14�����������ܲ�ǩ����timestamp�м���ֵ��ֵ����Ӣ�Ĵ�Сд�����ַ�</p>
 * <p>15�����������ܲ�ǩ����timestamp�м���ֵ</p>
 * <p>16�����������ܲ�ǩ����timestamp�޼���ֵ</p>
 * <p>17�����������ܲ�ǩ����chnl�м���ֵ��ֵ����Ӣ�Ĵ�Сд�����ַ�</p>
 * <p>18�����������ܲ�ǩ����chnl�м���ֵ</p>
 * <p>19�����������ܲ�ǩ����chnl�޼���ֵ</p>
 * <p>20�����������ܲ�ǩ����cardNo�м���ֵ��ֵ����Ӣ�Ĵ�Сд�����ַ�</p>
 * <p>21�����������ܲ�ǩ����cardNo�м���ֵ</p>
 * <p>22�����������ܲ�ǩ����cardNo�޼���ֵ</p>
 * <p>23�����������ܲ�ǩ����mobile�м���ֵ��ֵ����Ӣ�Ĵ�Сд�����ַ�</p>
 * <p>24�����������ܲ�ǩ����mobile�м���ֵ</p>
 * <p>25�����������ܲ�ǩ����mobile�޼���ֵ</p>
 * <p>26�����������ܲ�ǩ����realNm�м���ֵ��ֵ����Ӣ�Ĵ�Сд�����ַ�</p>
 * <p>27�����������ܲ�ǩ����realNm�м���ֵ</p>
 * <p>28�����������ܲ�ǩ����realNm�޼���ֵ</p>
 * <p>29�����������ܲ�ǩ����certifId�м���ֵ��ֵ����Ӣ�Ĵ�Сд�����ַ�</p>
 * <p>30�����������ܲ�ǩ����certifId�м���ֵ</p>
 * <p>31�����������ܲ�ǩ����certifId�޼���ֵ</p>
 * <p>32�����������ܲ�ǩ����accType�м���ֵ��ֵ����Ӣ�Ĵ�Сд�����ַ�</p>
 * <p>33�����������ܲ�ǩ����accType�м���ֵ</p>
 * <p>34�����������ܲ�ǩ����accType�޼���ֵ</p>
 * <p>35�����������ܲ�ǩ����certType�м���ֵ��ֵ����Ӣ�Ĵ�Сд�����ַ�</p>
 * <p>36�����������ܲ�ǩ����certType�м���ֵ</p>
 * <p>37�����������ܲ�ǩ����certType�޼���ֵ</p>
 * <p>38�����������ܲ�ǩ��������֤��DNΪ�ջ�null</p>
 * <p>39�����������ܲ�ǩ����ǩ��֤��DNΪ�ջ�null</p>
 * <p>40�����������ܲ�ǩ��������֤��DN������</p>
 * <p>41�����������ܲ�ǩ����ǩ��֤��DN������</p>
 */
@Test(groups = "abcjew.cupcqpencryptandsign")
public class TestCUPCQPEncryptAndSign {
    static String ip, port, password;
    static String host, sftp_port, sftp_password, sftp_user;
    Random random = new Random();

    NetSignServerInit init = new NetSignServerInit();
    UpkiAgent agent;
    SFTPFile tmp = new SFTPFile();
    JsonValueString jsonValue = new JsonValueString();

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
//        tmp.downFile(sftp_user, host, sftp_port, sftp_password, ParameterUtil.sftpkeystorepath,
//                ParameterUtil.keystorepath);
        System.out.println("NetSignServerInit OK");
    }

    /**
     * ���������ܲ�ǩ����ʹ������״̬֤��DN���м��ܲ�ǩ��
     *
     * @param dn ����״̬֤��DN
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal", dataProvider = "all-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPCQPEncryptAndSign_01(String dn) {
        System.out.println("���������ܲ�ǩ����ʹ������״̬֤��DN���м��ܲ�ǩ��");

        String jsonMessage = CUPCQPEncAndsignMessage;
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonMessage, dn, dn);
            if (!upkiResult.getBoolResult() || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����ʹ������״̬֤��SN���м��ܲ�ǩ��
     *
     * @param sn ����״̬֤��SN
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal", dataProvider = "all-sn", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPCQPEncryptAndSign_02(String sn) {
        System.out.println("���������ܲ�ǩ����ʹ������״̬֤��DN���м��ܲ�ǩ��");

        String jsonMessage = CUPCQPEncAndsignMessage;
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonMessage, sn, sn);
            if (!upkiResult.getBoolResult() || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����ʹ������״̬֤��Bankcode���м��ܲ�ǩ��
     *
     * @param bankcode ����״̬֤��Bankcode
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal", dataProvider = "all-bankcode", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPCQPEncryptAndSign_03(String bankcode) {
        System.out.println("���������ܲ�ǩ����ʹ������״̬֤��Bankcode���м��ܲ�ǩ��");

        String jsonMessage = CUPCQPEncAndsignMessage;
        if ("10year".equals(bankcode)) {
            return;
        }
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonMessage, bankcode, bankcode);
            if (!upkiResult.getBoolResult() || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ�������ں�������֤��Bankcode���м��ܲ�ǩ��
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_04() {
        System.out.println("���������ܲ�ǩ�������ں�������֤��Bankcode���м��ܲ�ǩ��");

        String jsonMessage = CUPCQPEncAndsignMessage;
        String bankcode = "10year";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonMessage, bankcode, bankcode);
            if (upkiResult.getReturnCode() != -100203) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����appId�м���ֵ��ֵ����Ӣ�Ĵ�Сд�����ַ�
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_05() {
        System.out.println("���������ܲ�ǩ����appId�м���ֵ��ֵ����Ӣ�Ĵ�Сд�����ַ�");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("��Ӣ��abcABC!@#");
        jsonObject.put("appId", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����appId�м���ֵ
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_06() {
        System.out.println("���������ܲ�ǩ����appId�м���ֵ");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("");
        jsonObject.put("appId", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����appId�޼���ֵ
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_07() {
        System.out.println("���������ܲ�ǩ����appId�޼���ֵ");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonObject.remove("appId");
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����indUsrId�м���ֵ��ֵ����Ӣ�Ĵ�Сд�����ַ�
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_08() {
        System.out.println("���������ܲ�ǩ����indUsrId�м���ֵ��ֵ����Ӣ�Ĵ�Сд�����ַ�");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("��Ӣ��abcABC!@#");
        jsonObject.put("indUsrId", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����indUsrId�м���ֵ
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_09() {
        System.out.println("���������ܲ�ǩ����indUsrId�м���ֵ");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("");
        jsonObject.put("indUsrId", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����indUsrId�޼���ֵ
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_10() {
        System.out.println("���������ܲ�ǩ����indUsrId�޼���ֵ");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonObject.remove("indUsrId");
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����nonceStr�м���ֵ��ֵ����Ӣ�Ĵ�Сд�����ַ�
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_11() {
        System.out.println("���������ܲ�ǩ����nonceStr�м���ֵ��ֵ����Ӣ�Ĵ�Сд�����ַ�");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("��Ӣ��abcABC!@#");
        jsonObject.put("nonceStr", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����nonceStr�м���ֵ
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_12() {
        System.out.println("���������ܲ�ǩ����nonceStr�м���ֵ");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("");
        jsonObject.put("nonceStr", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����nonceStr�޼���ֵ
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_13() {
        System.out.println("���������ܲ�ǩ����nonceStr�޼���ֵ");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonObject.remove("nonceStr");
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����timestamp�м���ֵ��ֵ����Ӣ�Ĵ�Сд�����ַ�
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_14() {
        System.out.println("���������ܲ�ǩ����timestamp�м���ֵ��ֵ����Ӣ�Ĵ�Сд�����ַ�");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("��Ӣ��abcABC!@#");
        jsonObject.put("timestamp", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����timestamp�м���ֵ
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_15() {
        System.out.println("���������ܲ�ǩ����timestamp�м���ֵ");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("");
        jsonObject.put("timestamp", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����timestamp�޼���ֵ
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_16() {
        System.out.println("���������ܲ�ǩ����timestamp�޼���ֵ");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonObject.remove("timestamp");
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����chnl�м���ֵ��ֵ����Ӣ�Ĵ�Сд�����ַ�
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_17() {
        System.out.println("���������ܲ�ǩ����chnl�м���ֵ��ֵ����Ӣ�Ĵ�Сд�����ַ�");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("��Ӣ��abcABC!@#");
        jsonObject.put("chnl", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����chnl�м���ֵ
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_18() {
        System.out.println("���������ܲ�ǩ����chnl�м���ֵ");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("");
        jsonObject.put("chnl", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����chnl�޼���ֵ
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_19() {
        System.out.println("���������ܲ�ǩ����chnl�޼���ֵ");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonObject.remove("chnl");
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����cardNo�м���ֵ��ֵ����Ӣ�Ĵ�Сд�����ַ�
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_20() {
        System.out.println("���������ܲ�ǩ����cardNo�м���ֵ��ֵ����Ӣ�Ĵ�Сд�����ַ�");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("��Ӣ��abcABC!@#");
        jsonObject.put("cardNo", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����cardNo�м���ֵ
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_21() {
        System.out.println("���������ܲ�ǩ����cardNo�м���ֵ");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("");
        jsonObject.put("cardNo", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����cardNo�޼���ֵ
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_22() {
        System.out.println("���������ܲ�ǩ����cardNo�޼���ֵ");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonObject.remove("cardNo");
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����mobile�м���ֵ��ֵ����Ӣ�Ĵ�Сд�����ַ�
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_23() {
        System.out.println("���������ܲ�ǩ����mobile�м���ֵ��ֵ����Ӣ�Ĵ�Сд�����ַ�");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("��Ӣ��abcABC!@#");
        jsonObject.put("mobile", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����mobile�м���ֵ
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_24() {
        System.out.println("���������ܲ�ǩ����mobile�м���ֵ");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("");
        jsonObject.put("mobile", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����mobile�޼���ֵ
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_25() {
        System.out.println("���������ܲ�ǩ����mobile�޼���ֵ");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonObject.remove("mobile");
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����realNm�м���ֵ��ֵ����Ӣ�Ĵ�Сд�����ַ�
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_26() {
        System.out.println("���������ܲ�ǩ����realNm�м���ֵ��ֵ����Ӣ�Ĵ�Сд�����ַ�");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("��Ӣ��abcABC!@#");
        jsonObject.put("realNm", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����realNm�м���ֵ
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_27() {
        System.out.println("���������ܲ�ǩ����realNm�м���ֵ");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("");
        jsonObject.put("realNm", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����realNm�޼���ֵ
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_28() {
        System.out.println("���������ܲ�ǩ����realNm�޼���ֵ");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonObject.remove("realNm");
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����certifId�м���ֵ��ֵ����Ӣ�Ĵ�Сд�����ַ�
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_29() {
        System.out.println("���������ܲ�ǩ����certifId�м���ֵ��ֵ����Ӣ�Ĵ�Сд�����ַ�");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("��Ӣ��abcABC!@#");
        jsonObject.put("certifId", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����certifId�м���ֵ
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_30() {
        System.out.println("���������ܲ�ǩ����certifId�м���ֵ");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("");
        jsonObject.put("certifId", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����certifId�޼���ֵ
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_31() {
        System.out.println("���������ܲ�ǩ����certifId�޼���ֵ");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonObject.remove("certifId");
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != -1061) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����accType�м���ֵ��ֵ����Ӣ�Ĵ�Сд�����ַ�
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_32() {
        System.out.println("���������ܲ�ǩ����accType�м���ֵ��ֵ����Ӣ�Ĵ�Сд�����ַ�");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("��Ӣ��abcABC!@#");
        jsonObject.put("accType", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����accType�м���ֵ
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_33() {
        System.out.println("���������ܲ�ǩ����accType�м���ֵ");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("");
        jsonObject.put("accType", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����accType�޼���ֵ
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_34() {
        System.out.println("���������ܲ�ǩ����accType�޼���ֵ");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonObject.remove("accType");
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����certType�м���ֵ��ֵ����Ӣ�Ĵ�Сд�����ַ�
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_35() {
        System.out.println("���������ܲ�ǩ����certType�м���ֵ��ֵ����Ӣ�Ĵ�Сд�����ַ�");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("��Ӣ��abcABC!@#");
        jsonObject.put("certType", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����certType�м���ֵ
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_36() {
        System.out.println("���������ܲ�ǩ����certType�м���ֵ");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonValue.setValue("");
        jsonObject.put("certType", jsonValue);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����certType�޼���ֵ
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_37() {
        System.out.println("���������ܲ�ǩ����certType�޼���ֵ");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        jsonObject.remove("certType");
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn);
            if (upkiResult.getReturnCode() != 0) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ��������֤��DNΪ�ջ�null
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPCQPEncryptAndSign_38(String encDn) {
        System.out.println("���������ܲ�ǩ��������֤��DNΪ�ջ�null");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), encDn, dn);
            if (upkiResult.getReturnCode() != -1026) {
                if (upkiResult.getReturnCode() != 0) {
                    Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("���������ܲ�ǩ��(CUPCQPEncryptAndSign)������֤��DN����null����ִ�гɹ�");
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����ǩ��֤��DNΪ�ջ�null
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPCQPEncryptAndSign_39(String signDn) {
        System.out.println("���������ܲ�ǩ����ǩ��֤��DNΪ�ջ�null");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, signDn);
            if (upkiResult.getReturnCode() != -1026) {
                if (upkiResult.getReturnCode() != 0) {
                    Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("���������ܲ�ǩ��(CUPCQPEncryptAndSign)��ǩ��֤��DN����ջ�null����ִ�гɹ�");
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ��������֤��DN������
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_40() {
        System.out.println("���������ܲ�ǩ��������֤��DN������");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        String dn1 = "CN=123";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn1, dn);
            if (upkiResult.getReturnCode() != -100203) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ���������ܲ�ǩ����ǩ��֤��DN������
     */
    @Test(groups = "abcjew.cupcqpencryptandsign.normal")
    public void testCUPCQPEncryptAndSign_41() {
        System.out.println("���������ܲ�ǩ����ǩ��֤��DN������");
        JsonObject jsonObject = Utils.getJsonObject(CUPCQPEncAndsignMessage);
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        String dn1 = "CN=123";
        try {
            UpkiResult upkiResult = agent.CUPCQPEncryptAndSign(jsonObject.toJson(), dn, dn1);
            if (upkiResult.getReturnCode() != -100204) {
                Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ܲ�ǩ��ʧ�ܣ�" + e.getMessage());
        }
    }
}
