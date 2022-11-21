import { useState, React } from "react";
import { Modal, Button, InputGroup, FormControl } from "react-bootstrap";

const EmailModal = (props) => {
  const [emailAddress, setEmailAddress] = useState("");

  if (!props.show) {
    return null;
  }

  return (
    <div>
      <Modal show={props.show} onHide={props.handleClose} centered>
        <Modal.Header closeButton>
          <Modal.Title>Send config via mail</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <InputGroup size="mb-3" className="mb-3" id="emailModal">
            <InputGroup.Text>Email</InputGroup.Text>
            <FormControl
              value={emailAddress}
              onChange={(e) => setEmailAddress(e.target.value)}
            />
          </InputGroup>
        </Modal.Body>
        <Modal.Footer className="emailbuttons">
          <Button variant="outline-secondary" onClick={props.handleClose}>
            Close
          </Button>
          <Button
            variant="outline-warning"
            onClick={() => {
              props.handleClose();
              props.sendEmail(emailAddress);
            }}
          >
            Send Email
          </Button>
        </Modal.Footer>
      </Modal>
    </div>
  );
};

export default EmailModal;
