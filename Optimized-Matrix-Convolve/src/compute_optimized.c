#include <omp.h>
#include <x86intrin.h>

#include "compute.h"

// Computes the dot product of vec1 and vec2, both of size n
int32_t dot(uint32_t n, int32_t *vec1, int32_t *vec2) {
  // TODO: implement dot product of vec1 and vec2, both of size n
    __m256i sum = _mm256_setzero_si256();
    #pragma omp parallel
    {
        __m256i priv_sum = _mm256_setzero_si256();
        #pragma omp for
        for (uint32_t i = 0; i < n / 8 * 8; i += 8) {
            __m256i a_8 = _mm256_loadu_si256((__m256i*) (vec1 + i));
            __m256i b_8 = _mm256_loadu_si256((__m256i*) (vec2 + i));
            __m256i mul = _mm256_mullo_epi32(a_8, b_8);
            priv_sum = _mm256_add_epi32(priv_sum, mul);
        }
        #pragma omp critical
        sum = _mm256_add_epi32(sum, priv_sum);
    }
    int32_t rest = 0;
    for (int i = n / 8 * 8; i < n; i++) {
        rest += vec1[i] * vec2[i];
    }
    int32_t temp[8];
    _mm256_storeu_si256((__m256i*) temp, sum);
    return temp[0] +  temp[1] +  temp[2] +  temp[3] + temp[4] +  temp[5] +  temp[6] +  temp[7] + rest;
}

void reverse(int32_t* arr, int n)
{
    for (int low = 0, high = n - 1; low < high; low++, high--)
    {
        int temp = arr[low];
        arr[low] = arr[high];
        arr[high] = temp;
    }
}

// Computes the convolution of two matrices
int convolve(matrix_t *a_matrix, matrix_t *b_matrix, matrix_t **output_matrix) {
  // TODO: convolve matrix a and matrix b, and store the resulting matrix in
  // output_matrix
    int32_t* a_vec = a_matrix->data;
    int32_t* b_vec = b_matrix->data;
    int b_num = b_matrix->rows * b_matrix->cols;
    reverse(b_vec, b_num);
    int output_cols = a_matrix->cols - b_matrix->cols + 1;
    int output_rows = a_matrix->rows - b_matrix->rows + 1;
    if (output_rows <= 0 || output_cols <= 0) {
        return -1;
    }
    *output_matrix = malloc(sizeof(matrix_t));
    (*output_matrix)->rows = output_rows;
    (*output_matrix)->cols = output_cols;
    int size = output_cols * output_rows;
    (*output_matrix)->data = malloc(sizeof(int32_t) * size);
    int b_numr = b_matrix->rows;
    int b_numc = b_matrix->cols;
    int* A_vec = malloc(sizeof(int) * b_numc);
    // #pragma omp for
    for (int curr_row = 0; curr_row < output_rows; curr_row++) {
        for(int curr_col = 0; curr_col < output_cols; curr_col++) {
            int sum = 0;
            for (int i = 0; i < b_numr; i++) {
                for (int j = 0; j < b_numc; j++) {
                    *(A_vec + j) = a_vec[j + curr_col + (i + curr_row) * a_matrix->cols];
                }
                sum += dot(b_numc, A_vec, (b_vec + i * b_numc));
            }
            (*output_matrix)->data[output_cols * curr_row + curr_col] = sum;
/*
            int sum = 0;
            int a_row = curr_row;
            int a_col = curr_col;
            for (int k = 0; k < b_num / 8 * 8; k += 8) { // for each element k in b_matrix
                int32_t* a_8digits = malloc(sizeof(int) * 8);
                for (int i = k; i < k + 8; i++) {
                    int b_row = i / b_numc;
                    int b_col = i - i / b_numc * b_numc;
                    if (b_col == 0) {
                        a_col = curr_col;
                        a_row++;
                    }
                    int a_index = a_col + a_row * a_matrix->cols;
                    a_8digits[i - k] = a_vec[a_index];
                    a_col++;
                }
                __m256i b_8digits = _mm256_loadu_si256((__m256i*) (b_vec + k));
                sum += dot(8, a_8digits, b_8digits);
            }
            a_row = curr_row;
            a_col = curr_col;
            for (int k = b_num / 8 * 8; k < b_num; k++) {
                sum += a_vec[k] * b_vec[b_num - k - 1];
            }
            (*output_matrix)->data[curr_col + curr_row * output_cols] = sum;
            */
        }
    }
    return 0;
}

// Executes a task
int execute_task(task_t *task) {
  matrix_t *a_matrix, *b_matrix, *output_matrix;

  if (read_matrix(get_a_matrix_path(task), &a_matrix))
    return -1;
  if (read_matrix(get_b_matrix_path(task), &b_matrix))
    return -1;

  if (convolve(a_matrix, b_matrix, &output_matrix))
    return -1;

  if (write_matrix(get_output_matrix_path(task), output_matrix))
    return -1;

  free(a_matrix->data);
  free(b_matrix->data);
  free(output_matrix->data);
  free(a_matrix);
  free(b_matrix);
  free(output_matrix);
  return 0;
}
