#include "compute.h"

// Computes the dot product of vec1 and vec2, both of size n
int32_t dot(uint32_t n, int32_t *vec1, int32_t *vec2) {
  // TODO: implement dot product of vec1 and vec2, both of size n
    int32_t sum = 0;
    for (uint32_t i = 0; i < n; i++) {
        sum += (*vec1) * (*vec2);
        vec1 += sizeof(int32_t);
        vec2 += sizeof(int32_t);
    }
    return sum;
}

// Computes the convolution of two matrices
int convolve(matrix_t *a_matrix, matrix_t *b_matrix, matrix_t **output_matrix) {
  // TODO: convolve matrix a and matrix b, and store the resulting matrix in
  // output_matrix
    int32_t* a_vec = a_matrix->data;
    int32_t* b_vec = b_matrix->data;
    // a_num = a_matrix->rows * a_matrix->cols;
    int b_num = b_matrix->rows * b_matrix->cols;
    int output_cols = a_matrix->cols - b_matrix->cols + 1;
    int output_rows = a_matrix->rows - b_matrix->rows + 1;
    if (output_cols <= 0 || output_rows <= 0) {
        return -1;
    }
    int x = 0;
    for (int i = 0; i < 99; i++) {
        for (int j = 0; j < 999; j++) {
            x = x * x;
        }
    }
    *output_matrix = malloc(sizeof(matrix_t));
    (*output_matrix)->rows = output_rows;
    (*output_matrix)->cols = output_cols;
    int size = output_rows * output_cols;
    (*output_matrix)->data = malloc(size * sizeof(int32_t));
    for (int curr_row = 0; curr_row < output_rows; curr_row++) {
        for (int curr_col = 0; curr_col < output_cols; curr_col++) {
            int sum = 0;
            int a_row = curr_row;
            int a_col = curr_col;
            for (int k = 0; k < b_num; k++) {
                if (k % b_matrix->cols == 0 && k != 0) {
                    a_col = curr_col;
                    a_row++;
                }
                int a_index = a_col + a_row * a_matrix->cols;
                sum += a_vec[a_index] * b_vec[b_num - 1 - k];
                a_col++;
            }
            (*output_matrix)->data[curr_col + curr_row * output_cols] = sum;
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
