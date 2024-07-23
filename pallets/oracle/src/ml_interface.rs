use pyo3::prelude::*;

#[pyclass]
pub struct RustMLInterface {
    py_ml_pipeline: PyObject,
}

#[pymethods]
impl RustMLInterface {
    #[new]
    fn new() -> PyResult<Self> {
        Python::with_gil(|py| {
            let ml_module = PyModule::import(py, "main_ml")?;
            let py_ml_pipeline = ml_module.getattr("MLPipeline")?.call0()?;
            Ok(RustMLInterface { py_ml_pipeline })
        })
    }

    fn process_data(&self, data: Vec<f64>) -> PyResult<Vec<f64>> {
        Python::with_gil(|py| {
            let result = self.py_ml_pipeline
                .call_method1(py, "process", (data,))?
                .extract(py)?;
            Ok(result)
        })
    }
}