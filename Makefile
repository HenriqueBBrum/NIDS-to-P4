
RULES_URL=https://www.snort.org/downloads/community/snort3-community-rules.tar.gz

TARGET_DIR=target
DATASET_DIR=dataset

COMMUNITY_OUTPUT_FILE=${DATASET_DIR}/comunnity-rules.csv

# Improve registered download
REGISTERED_RULES_FILE=${TARGET_DIR}/rules
REGISTERED_OUTPUT_FILE=${DATASET_DIR}/registered-rules.csv

COMMUNITY_RULES_FILE=etc/rules/snort3-community.rules
REGISTERED_RULES_FILE=target/registered
EMERGING_RULES_FILE=target/emerging/rules

SNORT_CONFIG=etc/config

all: parse.csv

$(TARGET_DIR):
	mkdir -p ${TARGET_DIR}

$(DATASET_DIR):
	mkdir -p ${DATASET_DIR}

$(COMMUNITY_RULES_FILE): $(TARGET_DIR)
	curl -L "${RULES_URL}" | tar -xz -C ${TARGET_DIR}

compiler.community: $(DATASET_DIR)
	python3 src/compiler/compiler.py ${SNORT_CONFIG} ${COMMUNITY_RULES_FILE}

compiler.community.p4id: $(DATASET_DIR)
	python3 src/main/python/compiler_p4id.py ${SNORT_CONFIG} ${COMMUNITY_RULES_FILE}

compiler.registered: $(DATASET_DIR)
	python3 src/main/python/compiler.py ${SNORT_CONFIG} ${REGISTERED_RULES_FILE}

compiler.emerging: $(DATASET_DIR)
	python3 src/main/python/compiler.py ${SNORT_CONFIG} ${EMERGING_RULES_FILE}

compiler.community.individual: $(DATASET_DIR)
	python3 src/main/python/compiler_individual.py ${SNORT_CONFIG} ${COMMUNITY_RULES_FILE}

compiler.registered.individual: $(DATASET_DIR)
	python3 src/main/python/compiler_individual.py ${SNORT_CONFIG} ${REGISTERED_RULES_FILE}

docker.build:
	docker build -t p4lang/p4app:p4snort .

p4.run:
	date
	P4APP_IMAGE=p4lang/p4app:p4snort \
	P4APP_LOGDIR="./$(TARGET_DIR)/experiments/logs" \
	p4app run src/main/p4/p4snort
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