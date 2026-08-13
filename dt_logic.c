Dang huan luyen mo hinh Decision Tree (max_depth=5) ...
----------------------------------------
Accuracy tren tap test : 0.7808
----------------------------------------

Cau truc DT thu duoc (Cac luat if-else):
|--- tcp_flags <= 0.74
|   |--- dst_port <= -1.96
|   |   |--- pkt_len <= 0.00
|   |   |   |--- ttl <= -2.17
|   |   |   |   |--- src_port <= -3.00
|   |   |   |   |   |--- class: 1
|   |   |   |   |--- src_port >  -3.00
|   |   |   |   |   |--- class: 0
|   |   |   |--- ttl >  -2.17
|   |   |   |   |--- tcp_flags <= -2.31
|   |   |   |   |   |--- class: 1
|   |   |   |   |--- tcp_flags >  -2.31
|   |   |   |   |   |--- class: 0
|   |   |--- pkt_len >  0.00
|   |   |   |--- src_port <= -1.41
|   |   |   |   |--- ttl <= -1.15
|   |   |   |   |   |--- class: 1
|   |   |   |   |--- ttl >  -1.15
|   |   |   |   |   |--- class: 0
|   |   |   |--- src_port >  -1.41
|   |   |   |   |--- pkt_len <= 0.33
|   |   |   |   |   |--- class: 0
|   |   |   |   |--- pkt_len >  0.33
|   |   |   |   |   |--- class: 1
|   |--- dst_port >  -1.96
|   |   |--- src_port <= 0.98
|   |   |   |--- pkt_len <= 1.33
|   |   |   |   |--- pkt_len <= -1.16
|   |   |   |   |   |--- class: 0
|   |   |   |   |--- pkt_len >  -1.16
|   |   |   |   |   |--- class: 0
|   |   |   |--- pkt_len >  1.33
|   |   |   |   |--- ttl <= 2.99
|   |   |   |   |   |--- class: 0
|   |   |   |   |--- ttl >  2.99
|   |   |   |   |   |--- class: 1
|   |   |--- src_port >  0.98
|   |   |   |--- dst_port <= 0.28
|   |   |   |   |--- tcp_flags <= -0.98
|   |   |   |   |   |--- class: 1
|   |   |   |   |--- tcp_flags >  -0.98
|   |   |   |   |   |--- class: 0
|   |   |   |--- dst_port >  0.28
|   |   |   |   |--- tcp_flags <= -1.13
|   |   |   |   |   |--- class: 0
|   |   |   |   |--- tcp_flags >  -1.13
|   |   |   |   |   |--- class: 1
|--- tcp_flags >  0.74
|   |--- src_port <= -1.29
|   |   |--- ttl <= -0.33
|   |   |   |--- src_port <= -3.18
|   |   |   |   |--- pkt_len <= 0.50
|   |   |   |   |   |--- class: 1
|   |   |   |   |--- pkt_len >  0.50
|   |   |   |   |   |--- class: 0
|   |   |   |--- src_port >  -3.18
|   |   |   |   |--- ttl <= -0.65
|   |   |   |   |   |--- class: 1
|   |   |   |   |--- ttl >  -0.65
|   |   |   |   |   |--- class: 1
|   |   |--- ttl >  -0.33
|   |   |   |--- dst_port <= 1.42
|   |   |   |   |--- pkt_len <= 0.08
|   |   |   |   |   |--- class: 1
|   |   |   |   |--- pkt_len >  0.08
|   |   |   |   |   |--- class: 0
|   |   |   |--- dst_port >  1.42
|   |   |   |   |--- ttl <= 1.65
|   |   |   |   |   |--- class: 0
|   |   |   |   |--- ttl >  1.65
|   |   |   |   |   |--- class: 1
|   |--- src_port >  -1.29
|   |   |--- dst_port <= 1.80
|   |   |   |--- ttl <= 0.76
|   |   |   |   |--- pkt_len <= 0.78
|   |   |   |   |   |--- class: 0
|   |   |   |   |--- pkt_len >  0.78
|   |   |   |   |   |--- class: 1
|   |   |   |--- ttl >  0.76
|   |   |   |   |--- ttl <= 1.80
|   |   |   |   |   |--- class: 0
|   |   |   |   |--- ttl >  1.80
|   |   |   |   |   |--- class: 0
|   |   |--- dst_port >  1.80
|   |   |   |--- src_port <= -0.16
|   |   |   |   |--- tcp_flags <= 1.40
|   |   |   |   |   |--- class: 1
|   |   |   |   |--- tcp_flags >  1.40
|   |   |   |   |   |--- class: 1
|   |   |   |--- src_port >  -0.16
|   |   |   |   |--- src_port <= 0.31
|   |   |   |   |   |--- class: 1
|   |   |   |   |--- src_port >  0.31
|   |   |   |   |   |--- class: 1


============================================================
MA C TU DONG SINH (San sang dua vao file XDP) : 
============================================================
int classify_packet(struct pkt_features *features){
	if (features->tcp_flags <=  0.7437) {
		if (features->dst_port <= -1.9603) {
			if (features->pkt_len <=  0.0016) {
				if (features->ttl <= -2.1651) {
					if (features->src_port <= -3.0003) {
						return XDP_DROP; // Du doan: Class1
					} else {
						return XDP_PASS; // Du doan: Class0
					}
				} else {
					if (features->tcp_flags <= -2.3060) {
						return XDP_DROP; // Du doan: Class1
					} else {
						return XDP_PASS; // Du doan: Class0
					}
				}
			} else {
				if (features->src_port <= -1.4052) {
					if (features->ttl <= -1.1478) {
						return XDP_DROP; // Du doan: Class1
					} else {
						return XDP_PASS; // Du doan: Class0
					}
				} else {
					if (features->pkt_len <=  0.3311) {
						return XDP_PASS; // Du doan: Class0
					} else {
						return XDP_DROP; // Du doan: Class1
					}
				}
			}
		} else {
			if (features->src_port <=  0.9812) {
				if (features->pkt_len <=  1.3321) {
					if (features->pkt_len <= -1.1638) {
						return XDP_PASS; // Du doan: Class0
					} else {
						return XDP_PASS; // Du doan: Class0
					}
				} else {
					if (features->ttl <=  2.9868) {
						return XDP_PASS; // Du doan: Class0
					} else {
						return XDP_DROP; // Du doan: Class1
					}
				}
			} else {
				if (features->dst_port <=  0.2828) {
					if (features->tcp_flags <= -0.9825) {
						return XDP_DROP; // Du doan: Class1
					} else {
						return XDP_PASS; // Du doan: Class0
					}
				} else {
					if (features->tcp_flags <= -1.1326) {
						return XDP_PASS; // Du doan: Class0
					} else {
						return XDP_DROP; // Du doan: Class1
					}
				}
			}
		}
	} else {
		if (features->src_port <= -1.2944) {
			if (features->ttl <= -0.3338) {
				if (features->src_port <= -3.1795) {
					if (features->pkt_len <=  0.4964) {
						return XDP_DROP; // Du doan: Class1
					} else {
						return XDP_PASS; // Du doan: Class0
					}
				} else {
					if (features->ttl <= -0.6483) {
						return XDP_DROP; // Du doan: Class1
					} else {
						return XDP_DROP; // Du doan: Class1
					}
				}
			} else {
				if (features->dst_port <=  1.4192) {
					if (features->pkt_len <=  0.0849) {
						return XDP_DROP; // Du doan: Class1
					} else {
						return XDP_PASS; // Du doan: Class0
					}
				} else {
					if (features->ttl <=  1.6547) {
						return XDP_PASS; // Du doan: Class0
					} else {
						return XDP_DROP; // Du doan: Class1
					}
				}
			}
		} else {
			if (features->dst_port <=  1.7970) {
				if (features->ttl <=  0.7608) {
					if (features->pkt_len <=  0.7794) {
						return XDP_PASS; // Du doan: Class0
					} else {
						return XDP_DROP; // Du doan: Class1
					}
				} else {
					if (features->ttl <=  1.8048) {
						return XDP_PASS; // Du doan: Class0
					} else {
						return XDP_PASS; // Du doan: Class0
					}
				}
			} else {
				if (features->src_port <= -0.1567) {
					if (features->tcp_flags <=  1.4026) {
						return XDP_DROP; // Du doan: Class1
					} else {
						return XDP_DROP; // Du doan: Class1
					}
				} else {
					if (features->src_port <=  0.3057) {
						return XDP_DROP; // Du doan: Class1
					} else {
						return XDP_DROP; // Du doan: Class1
					}
				}
			}
		}
	}
}
============================================================
