#include <omp.h>
#include <x86intrin.h>

#include "compute.h"

// Computes the dot product of vec1 and vec2, both of size n
int32_t dot(uint32_t n, int32_t *vec1, int32_t *vec2) {
  // TODO: implement dot product of vec1 and vec2, both of size n
    int32_t sum = 0;
    for (uint32_t i = 0; i < n; i++) {
        sum += vec1[i] * vec2[n - 1 - i];
    }
    return sum;
}

// Computes the convolution of two matrices
int convolve(matrix_t *a_matrix, matrix_t *b_matrix, matrix_t **output_matrix) {
  // TODO: convolve matrix a and matrix b, and store the resulting matrix in
  // output_matrix
    int32_t* a_vec = a_matrix->data;
    int32_t* b_vec = b_matrix->data;
    int b_num = b_matrix->rows * b_matrix->cols;
    int output_cols = a_matrix->cols - b_matrix->cols + 1;
    int output_rows = a_matrix->rows - b_matrix->rows + 1;
    if (output_cols <= 0 || output_rows <= 0) {
        return -1;
    }
    *output_matrix = malloc(sizeof(matrix_t));
    (*output_matrix)->rows = output_rows;
    (*output_matrix)->cols = output_cols;
    int size = output_rows * output_cols;
    (*output_matrix)->data = malloc(sizeof(int) * size);
    int b_numr = b_matrix->rows;
    int b_numc = b_matrix->cols;
    int* A_vec = malloc(sizeof(int) * b_num);
    #pragma omp for
    for (int curr_row = 0; curr_row < output_rows; curr_row++) {
        for (int curr_col = 0; curr_col < output_cols; curr_col++) {
            for (int i = 0; i < b_numr; i++) {
                for (int j = 0; j < b_numc; j++) {
                    *(A_vec + i * b_numc + j) = a_vec[j + curr_col + (i + curr_row) * a_matrix->cols];
                }
            }
            int sum = dot(b_num, A_vec, b_vec);
            (*output_matrix)->data[output_cols * curr_row + curr_col] = sum;
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
