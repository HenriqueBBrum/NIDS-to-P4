TARGET_DIR=target
DATASET_DIR=dataset

COMPILER_EXPERIMENTS_DIR=experiments/rule_compiler_evaluation
DATA_PLANE_EXPERIMENTS_DIR=experiments/data_plane_evaluation

SNORT_COMMUNITY_RULES=etc/rules/snort-community
SNORT2_EMERGING_RULES=etc/rules/snort2-emerging
REGISTERED_RULES=etc/rules/registered

SNORT_CONFIG=etc/config
COMPILER_GOAL=etc/compiler_goal.json

ifndef EVAL_RULE
EVAL_RULE = $(SNORT_COMMUNITY_RULES)
endif

build:
	mkdir -p ${TARGET_DIR} ${DATASET_DIR} ${COMPILER_EXPERIMENTS_DIR} ${DATA_PLANE_EXPERIMENTS_DIR}

compiler.community: 
	python3 src/compiler/compiler.py ${SNORT_CONFIG} ${SNORT_COMMUNITY_RULES} ${COMPILER_GOAL}

compiler.registered:
	python3 src/compiler/compiler.py ${SNORT_CONFIG} ${REGISTERED_RULES} ${COMPILER_GOAL}

compiler.emerging: 
	python3 src/compiler/compiler.py ${SNORT_CONFIG} ${SNORT2_EMERGING_RULES} ${COMPILER_GOAL}

compiler.eval:
	python3 src/compiler/compiler.py ${SNORT_CONFIG} ${EVAL_RULE} ${COMPILER_GOAL} ${COMPILER_EXPERIMENTS_DIR}

docker.build:
	docker build -t p4lang/p4app:p4snort .

p4.run:
	date
	P4APP_IMAGE=p4lang/p4app:p4snort \
	P4APP_LOGDIR="./$(TARGET_DIR)/experiments/logs" \
	p4app run src/p4
	date

p4.experiments.no_constraint: $(TARGET_DIR)
	@mkdir -p "$(TARGET_DIR)/experiments/no_constraint/monday" \
		"$(TARGET_DIR)/experiments/no_constraint/tuesday" \
		"$(TARGET_DIR)/experiments/no_constraint/wednesday" \
		"$(TARGET_DIR)/experiments/no_constraint/thursday" \
		"$(TARGET_DIR)/experiments/no_constraint/friday"

	@date
	P4APP_IMAGE=p4lang/p4app:p4snort \
	P4APP_LOGDIR="./$(TARGET_DIR)/experiments/no_constraint/monday" \
		p4app run src/main/p4/p4snort \
		--manifest experiments/no_constraint/p4app-monday.json \
		> "./$(TARGET_DIR)/experiments/no_constraint/monday/result" | true

	@date
	P4APP_IMAGE=p4lang/p4app:p4snort \
	P4APP_LOGDIR="./$(TARGET_DIR)/experiments/no_constraint/tuesday" \
		p4app run src/main/p4/p4snort \
		--manifest experiments/no_constraint/p4app-monday.json \
		> "./$(TARGET_DIR)/experiments/no_constraint/tuesday/result" | true

	@date