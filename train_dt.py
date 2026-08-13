import numpy as np
from sklearn.datasets import make_classification
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier, export_text
from sklearn.metrics import accuracy_score

# Tao du lieu gia lap (simulate) nhung mo phong giong network traffic , de luc in ra cau truc cay se giong du lieu that
FEATURE_NAMES = ["src_port","dst_port","pkt_len","tcp_flags","ttl"]
# Chu y : tuy feature la 5 , giong voi max_depth nhung hai cai la khac nhau , feature la chieu cua input , con maxdepth la do sau cua cay
X,y = make_classification(
	n_samples=20000,
	n_features=5,
	n_informative=4,
	n_redundant=1,
	n_classes=2,
	flip_y=0.05,
	random_state=42
)

#Chia tap train / test theo ty le 80/20
X_train,X_test,y_train,y_test = train_test_split(X,y,test_size=0.2,random_state=42)

#Khoi tao va train mo hinh clf
print("Dang huan luyen mo hinh Decision Tree (max_depth=5) ...")
clf = DecisionTreeClassifier(max_depth=5,random_state=42)
clf.fit(X_train,y_train)

#4.Danh gia mo hinh dua tren tap test 
y_pred = clf.predict(X_test)
accuracy = accuracy_score(y_test,y_pred)

print("-" * 40)
print(f"Accuracy tren tap test : {accuracy:.4f}")
print("-" * 40)

#5.In cau truc cay DT - clf
tree_rules = export_text(clf,feature_names=FEATURE_NAMES)
print("\nCau truc DT thu duoc (Cac luat if-else):")
print(tree_rules)


#Day 5. Chuyen doi tu cau truc cay thanh code C if/else de dua mo hinh vao eBPF Kernel
#Viet mot ham de tu dong chuyen doi code C
def generate_c_code(tree_model,feature_names):
	tree_ = tree_model.tree_
		
	print("\n" + "="*60)
	print("MA C TU DONG SINH (San sang dua vao file XDP) : ")
	print("="*60)

	#Gia dinh chung ta se goi cac feauture trich xuat duoc vao mot struct ten la pkt_features
	print("int classify_packet(struct pkt_features *features){")
	
	def recurse(node,depth):
		indent = "	" * depth

		# Kiem tra xem co phai nut la khong
		# Neu la nut la , thi se dua ra quyet dinh dua vao tree_.value(node_id)
		# Neu khong la nut la , thi se chuyen doi thanh code C if/else tuong ung
		if tree_.feature[node] != -2 : 
			name = feature_names[tree_.feature[node]]
			threshold =int(tree_.threshold[node])

			print(f"{indent}if (features->{name} <= {threshold}) {{")
			recurse(tree_.children_left[node],depth + 1)
			print(f"{indent}}} else {{")
			recurse(tree_.children_right[node],depth+1)
			print(f"{indent}}}")
		else:
			class_idx = np.argmax(tree_.value[node])
			action = "XDP_DROP" if class_idx == 1 else "XDP_PASS"
			print(f"{indent}return {action}; // Du doan: Class{class_idx}")
	recurse(0,1)
	print("}")
	print("="*60)

#Goi ham de sinh code
generate_c_code(clf,FEATURE_NAMES)
