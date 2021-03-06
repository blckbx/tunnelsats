import React from 'react'
import {ToggleButtonGroup,ToggleButton} from 'react-bootstrap'
const CountrySelector = (props) => {
  return (
    <div>
      <ToggleButtonGroup type="radio" name="options" id="countryselector" defaultValue={1}>
      <ToggleButton value={1} onClick={props.onClick} variant="secondary">
          πͺπΊ <br></br>EU
        </ToggleButton>
        <ToggleButton value={2} onClick={props.onClick} variant="secondary">
          πΊπΈ <br></br>USA
        </ToggleButton>
        <ToggleButton value={3} /*onClick={props.onClick}*/ variant="secondary" disabled>
          π¨π¦ <br></br>CAD
        </ToggleButton >
        <ToggleButton value={4} /*onClick={props.onClick}*/ variant="secondary" disabled>
          π¬π§ <br></br>UK
        </ToggleButton>
        <ToggleButton value={5} /*onClick={props.onClick}*/ variant="secondary" disabled>
          πΈπ¬ <br></br>SGP
        </ToggleButton>
      </ToggleButtonGroup>
     </div>
  )
}

export default CountrySelector
