# class3 evidence index

## 自动测试
- run-poly-tests.log：五个场景全部通过，ALL_SCENARIOS_PASS 5

## 无故障场景
- no-fault-s2-eth2_in-ipv4.pcap：S2 收到模态 1 副本
- no-fault-s2-eth3_in-ipv6.pcap：S2 收到模态 2 副本
- no-fault-s2-eth4_in-sr.pcap：S2 收到模态 3 副本
- no-fault-s2-eth1_out-restored.pcap：S2 向主机输出还原后的 IPv4/UDP
- no-fault-counters.txt：三模态 good=1，no_majority=0
- no-fault-evaluate.txt：三模态 HEALTHY

## 篡改场景
- corrupt-s2-eth1_out-restored.pcap：主机仍收到正确原文
- corrupt-s2-eth2_in-ipv4.pcap：模态 1 副本被篡改
- corrupt-counters.txt：mode1_bad=1，mode2/3_good=1
- corrupt-evaluate.txt：mode1 SUSPECT，mode2/3 HEALTHY

## 代码位置
- polymorphic.p4 MyIngress.do_adjudicate：2/3 多数状态机
- polymorphic.p4 MyIngress.restore_and_forward：透明还原
- polymorphic.p4 MyIngress.fault_table：故障注入
- mycontroller.py writeMulticastGroup / writeGatewayRoleRules / --fault：控制器配置
