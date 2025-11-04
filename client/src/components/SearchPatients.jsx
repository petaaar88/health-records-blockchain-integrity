import { Alert, Button } from "@mui/material";
import { useState } from "react";
import { useAuth } from "../contexts/AuthContext";
import HealthRecord from "./HealthRecord";
import PatientDetails from "./PatientDetails";
import ExternalHealthRecord from "./ExternalHealthRecord";

const SearchPatients = () => {
  const [error, setError] = useState("");
  const [patientDetails, setPatientDetails] = useState(null);
  const [ownedHealthRecords, setOwnedHealthRecords] = useState(null);
  const [externalHealthRecords, setExternalHealthRecords] = useState(null);
  const [loading, setLoading] = useState(false);
  const [patientPersonalID, setPatientPersonalID] = useState("");
  const handleOnChange = (e) => setPatientPersonalID(e.target.value);
  const { token } = useAuth();

  const fetchOwnedHealthRecords = async () => {
    try {
      const response = await fetch(
        import.meta.env.VITE_API_URL +
          `/api/health-records/patient/${patientPersonalID}?own=true`,
        {
          method: "get",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        }
      );

      const data = await response.json();

      if (response.ok) {
        setOwnedHealthRecords(data);
      } else {
        if (response.status == "500") setError("Internal Error");
        else setError(data.message);
      }
    } catch (err) {
      setError("Error. Try again.");
      console.error("Adding health record:", err);
    } finally {
      setLoading(false);
    }
  };

  const fetchExternalHealthRecords = async () => {
    try {
      const response = await fetch(
        import.meta.env.VITE_API_URL +
          `/api/health-records/patient/${patientPersonalID}`,
        {
          method: "get",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        }
      );

      const data = await response.json();

      if (response.ok) {
        setExternalHealthRecords(data);
      } else {
        if (response.status == "500") setError("Internal Error");
        else setError(data.message);
      }
    } catch (err) {
      setError("Error. Try again.");
      console.error("Adding health record:", err);
    } finally {
      setLoading(false);
    }
  };

  const fetchPatientDetails = async (patient_id) => {
    try {
      const response = await fetch(
        import.meta.env.VITE_API_URL + `/api/patients/personal_id/${patient_id}`,
        {
          method: "get",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        }
      );

      const data = await response.json();

      if (response.ok) {
        setPatientDetails(data);
      } else {
        if (response.status == "500") setError("Internal Error");
        else setError(data.message);
      }
    } catch (err) {
      setError("Error. Try again.");
      console.error("Adding health record:", err);
    } finally {
      setLoading(false);
    }
  };

  const handleSearching = () => {
    if (!patientPersonalID) return;

    fetchPatientDetails(patientPersonalID);

    fetchOwnedHealthRecords();
    fetchExternalHealthRecords();
  };
  return (
    <div>
      <h2 className="text-white text-2xl mb-8">Search Patients</h2>
      <div className="flex-row items-center  mb-6">
        {error && (
          <Alert
            severity="error"
            className="mb-6 w-120"
            onClose={() => setError("")}
          >
            {error}
          </Alert>
        )}
        <div>
          <input
            type="text"
            name="search_patinents"
            placeholder="Patient Personal ID"
            onChange={handleOnChange}
            value={patientPersonalID}
            className="w-90 px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-white disabled:bg-blue-800 disabled:cursor-not-allowed disabled:text-gray-400"
          />
          <Button variant="contained" onClick={handleSearching}>
            Search Patients
          </Button>
        </div>
      </div>
      {patientDetails ? (
        <div className="bg-white rounded-lg p-6 mb-8">
          {" "}
          <PatientDetails data={patientDetails} />
        </div>
      ) : null}
      <div className="flex justify-between">
        <div>
          {ownedHealthRecords ? (
            <h2 className="text-white text-2xl mb-6">Owned Health Records</h2>
          ) : null}
          {ownedHealthRecords?.health_records?.length == 0 ? (
            <p className="text-white">No Health Records</p>
          ) : (
            ownedHealthRecords?.health_records?.map((healthRecord) => (
              <HealthRecord
                key={healthRecord.health_record._id}
                data={healthRecord.health_record}
                secretKey={healthRecord.key}
              />
            ))
          )}
        </div>

        <div>
          {externalHealthRecords ? (
            <h2 className="text-white text-2xl mb-6">External Health Records</h2>
          ) : null}
          {externalHealthRecords?.blockchain_response?.length == 0 ? (
            <p className="text-white">No Health Records</p>
          ) : (
            externalHealthRecords?.blockchain_response?.map((healthRecord) => (
              <ExternalHealthRecord
                key={healthRecord.health_record_id}
                data={healthRecord}
                
              />
            ))
          )}
        </div>
      </div>
    </div>
  );
};

export default SearchPatients;
