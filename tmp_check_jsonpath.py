import jsonpath_ng.ext as jp

payload = {'powGetBpCms': 832.02246}
print('quoted', jp.parse("'powGetBpCms'").find(payload))
print('unquoted', jp.parse('powGetBpCms').find(payload))
payload2 = {'energyStrategyOperateMode': {'operateSelfPoweredOpen': True}}
print('quoted dotted', jp.parse("'energyStrategyOperateMode.operateSelfPoweredOpen'").find(payload2))
print('unquoted dotted', jp.parse('energyStrategyOperateMode.operateSelfPoweredOpen').find(payload2))
