



使用示例

        $data = [
            'out_trade_no' => '1492002348',
        ];
        $request = [
            'apiMethodName' => 'alipay.trade.query',
            'apiVersion' => "1.0",
            'apiParas' => [
                'biz_content' => json_encode($data, JSON_UNESCAPED_UNICODE),
            ],
        ];
        $c = new Alipay\AopClient("2016122204517457", storage_path('app/public/key/private_key.pem'), storage_path('app/public/key/public_key.pem'));
        $c->gatewayUrl = "https://openapi.alipaydev.com/gateway.do";

        $response= $c->execute($request);
        if ($response->alipay_trade_query_response->code == 10000) {
            echo 'success';
        } else {
            echo 'error';
        }
