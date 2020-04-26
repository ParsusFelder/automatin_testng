package qa.infosec.testng.netsign.dataprovider.util;

/**
 * @author zhaoyongzhi
 * @ClassName: JsonMessage
 * @date 2020-04-26 11:11
 * @Description: Json报文
 */
public class JsonMessage {
    /**
     * 银联云闪付Json报文
     */
    public static String CUPCQPEncAndsignMessage = "{ " +
            "\"appId\":\"appId\"," +
            "\"indUsrId\":\"indUsrId\"," +
            "\"nonceStr\":\"nonceStr\"," +
            "\"timestamp\":\"timestamp\"," +
            "\"chnl\":\"chnl\"," +
            "\"cardNo\":\"cardNo\"," +
            "\"mobile\":\"mobile\"," +
            "\"realNm\":\"realNm\"," +
            "\"certifId\":\"bbbbbbbbb\"," +
            "\"accType\":\"accType\"," +
            "\"certType\":\"certTypeaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\" " +
            "}";
}
