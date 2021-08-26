#!/bin/bash

###############################################################################

function check_size()
{
    local file_path="$1"

    if [ -s "$file_path" ]; then

        local file_size=$(stat -c "%s" "$file_path")

        if [[ $file_size -ge 64 ]] || [[ $(( $file_size % 64 )) -eq 0 ]]; then

            return 1

        fi
    fi

    return 0
}

###############################################################################

function is_valid_sha256()
{
    if [[ $1 =~ ^[a-fA-F0-9]{64}$ ]]; then

        return 1
    fi

    return 0
}

###############################################################################

function is_valid_file()
{
    local file_name="$1"

    if [ -s "$file_name" ]; then

        local tabs=$(head -1 "$file_name" | awk -F'\t' '{print NF-1}')

        if [ $tabs -eq 2 ]; then

            local sha256="$(head -1 "$file_name"| cut -f 2)"

            is_valid_sha256 $sha256

            return $?

        fi
    fi

    return 0
}

###############################################################################

function check_files()
{
    local array_files=("$@")
    local input_file

    for input_file in "${array_files[@]}"; do

        input_file="$(realpath "$input_file")"

        is_valid_file "$input_file"

        if [ $? -eq 0 ]; then
            echo
            echo "ERROR!! Invalid file $(realpath "$input_file")"
            echo
            echo "The file must exist and follow the following format per line:"
            echo
            echo '  FIELD1[TAB]SHA256[TAB]FIELD3'
            echo
            echo "Example:"
            echo
            echo "  $ head -1 rds241-sha256.txt"
            echo -e '  000000A9E47BD385A0A3685AA12C2DB6FD727A20\tD24186A60C409CDD22A8FB851867264C61A835B46B2805B614DAF64F3E01CFAE\tfemvo523.wav'
            echo

            return 0
        fi

    done

    return 1
}

###############################################################################

function check_requirements()
{
    local utilities=(binaryze awk realpath)
    local utility

    for utility in "${utilities[@]}"; do

        which $utility > /dev/null 2>&1

        if [ $? -eq 1 ]; then
            echo -e "\nERROR!! The $utility utility must be installed an accessible in PATH!!\n"
            return 0
        fi

    done

    return 1
}


###############################################################################
#
#
#
###############################################################################


RET_CODE=1

if [ $# -lt 2 ]; then
    echo -e "\nConvert several text source files with SHA256 hashes in NSRL format"
    echo "to binary format for use in the hashchecker server."
    echo -e "\nUsage:\n    $ $(basename "$0") [source1] [source2] ... [output_binary_file]\n"
    echo -e "\nExample:\n    $ $(basename "$0") rds241-sha256.txt sha256-win10.txt sha256-win7.txt sha256-ordered.bin\n"
    exit 1
fi

check_requirements

if [ $? -eq 1 ]; then
    INPUT_FILES=("${@:1:$(($#-1))}")
    OUTPUT_FILE=$(realpath "${@:$#}")
    HASH_ORDERED="sha256-ordered.txt"

    echo -n -e "\n** Checking output file..."

    if [ -s "$OUTPUT_FILE" ]; then
        echo -e " ERROR!! Output file '$OUTPUT_FILE' already exist!!\n"
        exit 1
    fi

    echo -n -e " OK\n\n** Checking input files..."

    check_files "${INPUT_FILES[@]}"

    if [ $? -eq 1 ]; then

        echo -e -n " OK\n\n** Creating ordered text file (could last several minutes)..."

        cut -f 2 ${INPUT_FILES[@]} | LC_ALL=C sort -u | tr --delete '\n' > "$HASH_ORDERED"

        check_size "$HASH_ORDERED"

        if [ $? -eq 1 ]; then

            echo -e -n " OK\n\n** Converting ordered text file to binary format (again, several minutes)..."

            binaryze -i "$HASH_ORDERED" -o "${OUTPUT_FILE}"

            RET_CODE=$?

            if [ $RET_CODE -eq 0 ]; then
                rm -f $HASH_ORDERED
                echo -e " OK\n\n** Script finished OK. Binary file successfully created on $OUTPUT_FILE\n"
                echo -e "** You can use this file as the input parameter for the hashchecker server this way:\n"
                echo -e "    $ hashchecker -p 25900 -i $OUTPUT_FILE\n"
            else
                echo -e " ERROR!! Check file $HASH_ORDERED for inconsistencies!!\n"
            fi

        else
            echo -e " ERROR!! Invalid intermediate file $HASH_ORDERED\n"
        fi
    fi

fi

exit $RET_CODE
