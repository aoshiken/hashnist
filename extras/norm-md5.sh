#!/bin/bash

###############################################################################

function check_size()
{
    local file_path="$1"

    if [ -s "$file_path" ]; then

        local file_size=$(stat -c "%s" "$file_path")

        if [[ $file_size -ge 32 ]] || [[ $(( $file_size % 32 )) -eq 0 ]]; then

            return 1

        fi
    fi

    return 0
}

###############################################################################

function is_valid_md5()
{
    if [[ $1 =~ ^[a-fA-F0-9]{32}$ ]]; then

        return 1
    fi

    return 0
}

###############################################################################

function is_valid_file()
{
    local file_name="$1"

    if [ -s "$file_name" ]; then

        local commas=$(head -1 "$file_name" | awk -F',' '{print NF-1}')

        if [ $commas -ge 2 ]; then

            local md5="$(head -1 "$file_name"| cut -d '"' -f 4)"

            is_valid_md5 $md5

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
            echo '  "FIELD1","MD5","FIELD3"'
            echo
            echo "Example:"
            echo
            echo "  $ head -1 NSRLFile.txt"
            echo '  "0000001FFEF4BE312BAB534ECA7AEAA3E4684D85","344428FA4BA313712E4CA9B16D089AC4","7516A25F",".text._ZNSt14overflow_errorC1ERKSs",33,219181,"362",""'
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
    echo -e "\nConvert several text source files with MD5 hashes in NSRL format"
    echo "to binary format for use in the hashchecker server."
    echo -e "\nUsage:\n    $ $(basename "$0") [source1] [source2] ... [output_binary_file]\n"
    echo -e "\nExample:\n    $ $(basename "$0") NSRLFile.txt md5-win10.txt md5-win7.txt md5-ordered.bin\n"
    exit 1
fi

check_requirements

if [ $? -eq 1 ]; then
    INPUT_FILES=("${@:1:$(($#-1))}")
    OUTPUT_FILE=$(realpath "${@:$#}")
    HASH_ORDERED="md5-ordered.txt"

    echo -n -e "\n** Checking output file..."

    if [ -s "$OUTPUT_FILE" ]; then
        echo -e " ERROR!! Output file '$OUTPUT_FILE' already exist!!\n"
        exit 1
    fi

    echo -n -e " OK\n\n** Checking input files..."

    check_files "${INPUT_FILES[@]}"

    if [ $? -eq 1 ]; then

        echo -e -n " OK\n\n** Creating ordered text file. Process could last several minutes..."

        cut -f 4 -d '"' ${INPUT_FILES[@]} | LC_ALL=C sort -u | tr --delete '\n' > "$HASH_ORDERED"

        check_size "$HASH_ORDERED"

        if [ $? -eq 1 ]; then

            echo -e -n " OK\n\n** Converting ordered text file to binary format..."

            binaryze --use-md5 -i "$HASH_ORDERED" -o "${OUTPUT_FILE}"

            RET_CODE=$?

            if [ $RET_CODE -eq 0 ]; then
                rm -f $HASH_ORDERED
                echo -e " OK\n\n** Script finished OK. Binary file successfully created on $OUTPUT_FILE\n"
                echo -e "** You can use this file as the input parameter for the hashchecker server this way:\n"
                echo -e "    $ hashchecker --use-md5 -i $OUTPUT_FILE\n"
            else
                echo -e " ERROR!! Check file $HASH_ORDERED for inconsistencies!!\n"
            fi

        else
            echo -e " ERROR!! Invalid intermediate file $HASH_ORDERED\n"
        fi
    fi

fi

exit $RET_CODE
