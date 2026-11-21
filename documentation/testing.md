# Testing, Integration, and Safety Verification

## Test suite

Run the complete suite from the repository root:

```powershell
pytest -v
```

The tests cover:

- `tests/test_setup.py`: required project folders and preservation of supplied CSV files.
- `tests/test_preprocessing.py`: label normalization, null/blank/duplicate removal, and stratified split behavior.
- `tests/test_features.py`: URL features and indicators, text normalization and saved model inference, and static HTML structure detection.
- `tests/test_fusion_and_prediction.py`: modality pass-through, confidence and availability weighting, three decision classes, escalation, real artifact loading, and input validation.
- `tests/test_app_integration.py`: app compilation/rendering, asset availability, backend prediction, empty-input warning, and all four navigation sections.

## Security and safety checks

- URL analysis uses local string parsing only. It does not issue HTTP requests, resolve DNS, or follow redirects.
- HTML is parsed with BeautifulSoup's built-in `html.parser`. Script tags are inspected as markup only; JavaScript is never executed and external resources are not fetched.
- `unsafe_allow_html=True` is limited to fixed, code-owned CSS and fixed verdict/status markup; no user-submitted values are interpolated into it. The app does not use `components.html` or `st.html`. User HTML is accepted as text and is never rendered as a webpage.
- The app does not save submitted content to local project files or a database. Inputs remain in the active Streamlit session while it is open.
- Predictions are decision-support signals, not definitive proof of malicious or safe content.

## Final Phase 5 verification

The final test run should report all tests passed with zero warnings. The final headless launch check is:

```powershell
streamlit run app.py --server.headless true
```

Successful startup prints a local URL, normally `http://localhost:8501`. The launch command does not open a browser automatically in headless mode; open the printed local URL for a defense/demo session.

This project has not been independently security audited. Safety statements above describe implemented behavior and test coverage, not a formal security certification.
